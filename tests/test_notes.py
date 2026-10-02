"""Note CRUD, ordering, pagination and concurrency control."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import Actor


def create_note(client: TestClient, actor: Actor, text: str) -> dict[str, object]:
    response = client.post("/notes", json={"note": text}, headers=actor.headers)
    assert response.status_code == 201, response.text
    return dict(response.json())


class TestCreate:
    def test_returns_the_stored_note(self, client: TestClient, alice: Actor) -> None:
        response = client.post(
            "/notes", json={"note": "Ship the rate limiter."}, headers=alice.headers
        )

        assert response.status_code == 201
        body = response.json()
        assert body["note"] == "Ship the rate limiter."
        assert body["user"] == alice.member
        assert body["team"] == "acme"
        assert body["version"] == 1
        assert body["date"] == body["updated_at"]
        assert body["date"].endswith("Z")

    def test_advertises_the_new_resource(self, client: TestClient, alice: Actor) -> None:
        response = client.post("/notes", json={"note": "Anything."}, headers=alice.headers)

        note_id = response.json()["id"]
        assert response.headers["Location"] == f"/notes/{note_id}"
        assert response.headers["ETag"] == '"1"'

    def test_identifiers_are_sortable_ulids(self, client: TestClient, alice: Actor) -> None:
        first = create_note(client, alice, "first")["id"]
        second = create_note(client, alice, "second")["id"]

        assert len(str(first)) == 26
        # The ordering guarantee the listing query depends on.
        assert str(first) < str(second)

    def test_whitespace_is_trimmed(self, client: TestClient, alice: Actor) -> None:
        body = create_note(client, alice, "   padded   ")

        assert body["note"] == "padded"

    def test_blank_note_is_rejected(self, client: TestClient, alice: Actor) -> None:
        response = client.post("/notes", json={"note": "   "}, headers=alice.headers)

        assert response.status_code == 422

    def test_note_beyond_the_length_limit_is_rejected(self, make_client: Any, sign_in: Any) -> None:
        client = make_client(NOTES_MAX_NOTE_LENGTH=10)
        alice = sign_in(client, "alice", "acme")

        response = client.post("/notes", json={"note": "x" * 11}, headers=alice.headers)

        assert response.status_code == 422

    def test_creating_requires_authentication(self, client: TestClient) -> None:
        response = client.post("/notes", json={"note": "Anything."})

        assert response.status_code == 401


class TestRead:
    def test_returns_a_note_by_id(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "Remember the milk.")

        response = client.get(f"/notes/{created['id']}", headers=alice.headers)

        assert response.status_code == 200
        assert response.json() == created
        assert response.headers["ETag"] == '"1"'

    def test_unknown_id_is_not_found(self, client: TestClient, alice: Actor) -> None:
        response = client.get("/notes/01M3Z4HMB1VS68PXB1QS3EA6GT", headers=alice.headers)

        assert response.status_code == 404

    def test_malformed_id_is_rejected_without_a_lookup(
        self, client: TestClient, alice: Actor
    ) -> None:
        response = client.get("/notes/not-a-ulid", headers=alice.headers)

        assert response.status_code == 422


class TestList:
    def test_returns_notes_newest_first(self, client: TestClient, alice: Actor) -> None:
        for text in ["oldest", "middle", "newest"]:
            create_note(client, alice, text)

        response = client.get("/notes", headers=alice.headers)

        assert response.status_code == 200
        assert [item["note"] for item in response.json()["items"]] == [
            "newest",
            "middle",
            "oldest",
        ]

    def test_shows_notes_from_every_team_member(
        self, client: TestClient, alice: Actor, bob: Actor
    ) -> None:
        create_note(client, alice, "from alice")
        create_note(client, bob, "from bob")

        response = client.get("/notes", headers=alice.headers)

        authors = {item["user"] for item in response.json()["items"]}
        assert authors == {alice.member, bob.member}

    def test_empty_team_returns_an_empty_page(self, client: TestClient, alice: Actor) -> None:
        response = client.get("/notes", headers=alice.headers)

        assert response.json() == {"items": [], "next_cursor": None}

    def test_pages_through_every_note_exactly_once(self, client: TestClient, alice: Actor) -> None:
        expected = [create_note(client, alice, f"note {index}")["id"] for index in range(7)]
        expected.reverse()

        collected: list[str] = []
        cursor: str | None = None
        for _ in range(10):  # generous bound; the loop should finish in three
            query = {"limit": 3} | ({"cursor": cursor} if cursor else {})
            page = client.get("/notes", params=query, headers=alice.headers).json()
            collected.extend(item["id"] for item in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break

        assert cursor is None
        assert collected == expected

    def test_page_size_is_capped(self, make_client: Any, sign_in: Any) -> None:
        """An oversized `limit` is clamped rather than rejected."""
        client = make_client(NOTES_MAX_PAGE_SIZE=2)
        alice = sign_in(client, "alice", "acme")
        for index in range(5):
            create_note(client, alice, f"note {index}")

        page = client.get("/notes", params={"limit": 100}, headers=alice.headers).json()

        assert len(page["items"]) == 2
        assert page["next_cursor"] is not None

    def test_search_matches_case_insensitively(self, client: TestClient, alice: Actor) -> None:
        create_note(client, alice, "Deploy the Rate Limiter")
        create_note(client, alice, "Buy milk")

        response = client.get("/notes", params={"q": "rate limiter"}, headers=alice.headers)

        assert [item["note"] for item in response.json()["items"]] == ["Deploy the Rate Limiter"]

    def test_search_with_no_matches_returns_nothing(self, client: TestClient, alice: Actor) -> None:
        create_note(client, alice, "Buy milk")

        response = client.get("/notes", params={"q": "quarterly revenue"}, headers=alice.headers)

        assert response.json()["items"] == []

    def test_malformed_cursor_is_rejected(self, client: TestClient, alice: Actor) -> None:
        response = client.get("/notes", params={"cursor": "!!!not-base64"}, headers=alice.headers)

        assert response.status_code == 422
        assert "cursor" in response.json()["detail"].lower()


class TestUpdate:
    def test_replaces_the_text_and_bumps_the_version(
        self, client: TestClient, alice: Actor
    ) -> None:
        created = create_note(client, alice, "before")

        response = client.patch(
            f"/notes/{created['id']}", json={"note": "after"}, headers=alice.headers
        )

        assert response.status_code == 200
        body = response.json()
        assert body["note"] == "after"
        assert body["version"] == 2
        assert body["updated_at"] >= str(body["date"])
        assert response.headers["ETag"] == '"2"'

    def test_creation_date_is_preserved(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")

        updated = client.patch(
            f"/notes/{created['id']}", json={"note": "after"}, headers=alice.headers
        ).json()

        assert updated["date"] == created["date"]
        assert updated["id"] == created["id"]

    def test_matching_if_match_succeeds(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")

        response = client.patch(
            f"/notes/{created['id']}",
            json={"note": "after"},
            headers={**alice.headers, "If-Match": '"1"'},
        )

        assert response.status_code == 200

    def test_stale_if_match_is_refused(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")
        client.patch(f"/notes/{created['id']}", json={"note": "v2"}, headers=alice.headers)

        # A second editor still holding version 1 must not silently clobber v2.
        response = client.patch(
            f"/notes/{created['id']}",
            json={"note": "v2 from a stale reader"},
            headers={**alice.headers, "If-Match": '"1"'},
        )

        assert response.status_code == 412
        assert client.get(f"/notes/{created['id']}", headers=alice.headers).json()["note"] == "v2"

    def test_wildcard_if_match_succeeds(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")

        response = client.patch(
            f"/notes/{created['id']}",
            json={"note": "after"},
            headers={**alice.headers, "If-Match": "*"},
        )

        assert response.status_code == 200

    def test_weak_etags_are_understood(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")

        response = client.patch(
            f"/notes/{created['id']}",
            json={"note": "after"},
            headers={**alice.headers, "If-Match": 'W/"1"'},
        )

        assert response.status_code == 200

    def test_malformed_if_match_is_rejected(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "before")

        response = client.patch(
            f"/notes/{created['id']}",
            json={"note": "after"},
            headers={**alice.headers, "If-Match": "not-a-version"},
        )

        assert response.status_code == 422

    def test_unknown_note_is_not_found(self, client: TestClient, alice: Actor) -> None:
        response = client.patch(
            "/notes/01M3Z4HMB1VS68PXB1QS3EA6GT", json={"note": "x"}, headers=alice.headers
        )

        assert response.status_code == 404


class TestDelete:
    def test_removes_the_note(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "temporary")

        response = client.delete(f"/notes/{created['id']}", headers=alice.headers)

        assert response.status_code == 204
        assert response.content == b""
        assert client.get(f"/notes/{created['id']}", headers=alice.headers).status_code == 404

    def test_deleting_twice_is_not_found(self, client: TestClient, alice: Actor) -> None:
        created = create_note(client, alice, "temporary")
        client.delete(f"/notes/{created['id']}", headers=alice.headers)

        response = client.delete(f"/notes/{created['id']}", headers=alice.headers)

        assert response.status_code == 404

    def test_unknown_note_is_not_found(self, client: TestClient, alice: Actor) -> None:
        response = client.delete("/notes/01M3Z4HMB1VS68PXB1QS3EA6GT", headers=alice.headers)

        assert response.status_code == 404
