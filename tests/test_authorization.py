"""The two rules that must never bend: team isolation and author-only edits.

These are the tests worth reading first. Everything else in the service is
recoverable; leaking one team's notes into another team is not.
"""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from tests.conftest import Actor
from tests.test_notes import create_note


class TestTeamIsolation:
    def test_another_team_cannot_read_your_note(
        self, client: TestClient, alice: Actor, carol: Actor
    ) -> None:
        note = create_note(client, alice, "acme internal roadmap")

        response = client.get(f"/notes/{note['id']}", headers=carol.headers)

        # 404 rather than 403: confirming the id exists would leak that another
        # team holds a note, which is itself information.
        assert response.status_code == 404

    def test_another_team_cannot_edit_your_note(
        self, client: TestClient, alice: Actor, carol: Actor
    ) -> None:
        note = create_note(client, alice, "acme internal roadmap")

        response = client.patch(
            f"/notes/{note['id']}", json={"note": "defaced"}, headers=carol.headers
        )

        assert response.status_code == 404
        assert client.get(f"/notes/{note['id']}", headers=alice.headers).json()["note"] == (
            "acme internal roadmap"
        )

    def test_another_team_cannot_delete_your_note(
        self, client: TestClient, alice: Actor, carol: Actor
    ) -> None:
        note = create_note(client, alice, "acme internal roadmap")

        response = client.delete(f"/notes/{note['id']}", headers=carol.headers)

        assert response.status_code == 404
        assert client.get(f"/notes/{note['id']}", headers=alice.headers).status_code == 200

    def test_listing_never_crosses_teams(
        self, client: TestClient, alice: Actor, carol: Actor
    ) -> None:
        create_note(client, alice, "acme note")
        create_note(client, carol, "globex note")

        acme = client.get("/notes", headers=alice.headers).json()
        globex = client.get("/notes", headers=carol.headers).json()

        assert [item["note"] for item in acme["items"]] == ["acme note"]
        assert [item["note"] for item in globex["items"]] == ["globex note"]

    def test_a_cursor_cannot_be_reused_against_another_team(
        self, client: TestClient, alice: Actor, carol: Actor
    ) -> None:
        """A cursor is client-visible state, so it is re-validated on the way in."""
        for index in range(3):
            create_note(client, alice, f"acme note {index}")
        cursor = client.get("/notes", params={"limit": 1}, headers=alice.headers).json()[
            "next_cursor"
        ]
        assert cursor

        response = client.get("/notes", params={"cursor": cursor}, headers=carol.headers)

        assert response.status_code == 422
        assert "does not belong" in response.json()["detail"]


class TestAuthorOnlyMutation:
    def test_a_teammate_can_read_your_note(
        self, client: TestClient, alice: Actor, bob: Actor
    ) -> None:
        note = create_note(client, alice, "shared with the team")

        response = client.get(f"/notes/{note['id']}", headers=bob.headers)

        assert response.status_code == 200
        assert response.json()["note"] == "shared with the team"

    def test_a_teammate_cannot_edit_your_note(
        self, client: TestClient, alice: Actor, bob: Actor
    ) -> None:
        note = create_note(client, alice, "alice's wording")

        response = client.patch(
            f"/notes/{note['id']}", json={"note": "bob's wording"}, headers=bob.headers
        )

        # 403 here, unlike the cross-team case: Bob can legitimately see this
        # note, so there is nothing to hide by pretending it is missing.
        assert response.status_code == 403
        assert client.get(f"/notes/{note['id']}", headers=alice.headers).json()["note"] == (
            "alice's wording"
        )

    def test_a_teammate_cannot_delete_your_note(
        self, client: TestClient, alice: Actor, bob: Actor
    ) -> None:
        note = create_note(client, alice, "alice's note")

        response = client.delete(f"/notes/{note['id']}", headers=bob.headers)

        assert response.status_code == 403
        assert client.get(f"/notes/{note['id']}", headers=alice.headers).status_code == 200

    def test_the_author_can_edit_and_delete(
        self, client: TestClient, alice: Actor, bob: Actor
    ) -> None:
        note = create_note(client, bob, "bob's note")

        assert (
            client.patch(
                f"/notes/{note['id']}", json={"note": "revised"}, headers=bob.headers
            ).status_code
            == 200
        )
        assert client.delete(f"/notes/{note['id']}", headers=bob.headers).status_code == 204

    def test_the_author_check_is_not_a_security_boundary(
        self, client: TestClient, sign_in: Any, alice: Actor
    ) -> None:
        """Asserted on purpose, because it follows from a shared team credential.

        A team's members share one API token, so whoever holds it can exchange
        it for a session attributed to any name - including a teammate's. The
        author check therefore prevents accidents, not a deliberate edit by
        someone already inside the team. Closing this needs per-member
        credentials, not a stricter condition expression.

        Cross-team isolation is unaffected: the team claim comes from the
        token, never from the request.
        """
        note = create_note(client, alice, "alice's wording")
        impersonating_alice = sign_in(client, alice.member, "acme")

        response = client.patch(
            f"/notes/{note['id']}",
            json={"note": "edited by someone claiming to be alice"},
            headers=impersonating_alice.headers,
        )

        assert response.status_code == 200
