"""Password hashing properties that the HTTP tests cannot show directly."""

from __future__ import annotations

from notes.auth.passwords import hash_password, verify_password

ROUNDS = 4


def test_a_correct_password_verifies() -> None:
    stored = hash_password("correct-horse-battery-staple", rounds=ROUNDS)

    assert verify_password("correct-horse-battery-staple", stored)


def test_a_wrong_password_does_not_verify() -> None:
    stored = hash_password("correct-horse-battery-staple", rounds=ROUNDS)

    assert not verify_password("correct-horse-battery-stapler", stored)


def test_the_same_password_hashes_differently_each_time() -> None:
    """Distinct salts, so identical passwords are not identifiable in the table."""
    first = hash_password("same-password-twice", rounds=ROUNDS)
    second = hash_password("same-password-twice", rounds=ROUNDS)

    assert first != second
    assert verify_password("same-password-twice", first)
    assert verify_password("same-password-twice", second)


def test_long_passwords_are_not_truncated() -> None:
    """bcrypt alone stops at 72 bytes; the SHA-256 pre-hash is what prevents it.

    Without that step these two passwords would share their first 72 bytes and
    verify against each other's hash.
    """
    base = "x" * 72
    stored = hash_password(base + "first-tail", rounds=ROUNDS)

    assert verify_password(base + "first-tail", stored)
    assert not verify_password(base + "second-tail", stored)


def test_a_null_byte_does_not_truncate_the_password() -> None:
    """bcrypt treats input as a C string and would stop at the NUL."""
    stored = hash_password("prefix\x00secret", rounds=ROUNDS)

    assert verify_password("prefix\x00secret", stored)
    assert not verify_password("prefix\x00different", stored)


def test_an_unparseable_stored_hash_is_a_failed_check_not_a_crash() -> None:
    assert not verify_password("anything", "this-is-not-a-bcrypt-hash")
