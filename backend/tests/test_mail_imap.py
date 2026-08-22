"""IMAP connect must fail fast with a readable error, not hang the dashboard."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from app.mail_guard import IMAP_TIMEOUT_SECONDS, MailInboxMonitor, _friendly_imap_error, _open_imap


class FakeImap:
    def __init__(self, host: str = "", timeout: float | None = None) -> None:
        self.host = host
        self.timeout = timeout

    def login(self, username: str, password: str) -> tuple[str, list[bytes]]:
        return "OK", [b"Logged in"]

    def select(self, mailbox: str, readonly: bool = True) -> tuple[str, list[bytes]]:
        return "OK", [b"1"]

    def logout(self) -> tuple[str, list[bytes]]:
        return "BYE", []


class MailImapTests(unittest.TestCase):
    def test_open_imap_sets_timeout(self) -> None:
        with patch("app.mail_guard.imaplib.IMAP4_SSL", FakeImap):
            client = _open_imap("imap.gmail.com")
        self.assertEqual(client.timeout, IMAP_TIMEOUT_SECONDS)
        self.assertEqual(client.host, "imap.gmail.com")

    def test_auth_error_tells_user_to_use_app_password(self) -> None:
        message = _friendly_imap_error(
            Exception("[AUTHENTICATIONFAILED] Invalid credentials (Failure)"),
            host="imap.gmail.com",
        )
        self.assertIn("App Password", message)
        self.assertNotIn("AUTHENTICATIONFAILED", message)

    def test_timeout_error_is_readable(self) -> None:
        message = _friendly_imap_error(TimeoutError("timed out"), host="imap.gmail.com")
        self.assertIn("12 seconds", message)
        self.assertIn("993", message)

    def test_stop_does_not_deadlock(self) -> None:
        monitor = MailInboxMonitor()
        status = monitor.stop()
        self.assertFalse(status["enabled"])
        self.assertIn("stopped", status["last_message"].lower())

    def test_connect_schema_accepts_16_char_app_password(self) -> None:
        from pydantic import ValidationError

        from app.schemas import MailImapConnectRequest

        req = MailImapConnectRequest(
            host="imap.gmail.com",
            username="you@gmail.com",
            password="abcdefghijklmnop",
        )
        self.assertEqual(len(req.password), 16)
        self.assertEqual(req.interval_seconds, 20)

        # Older UI sent a 12s poll interval; that must not block Gmail login.
        allowed = MailImapConnectRequest(
            host="imap.gmail.com",
            username="you@gmail.com",
            password="abcd efgh ijkl mnop",
            interval_seconds=12,
        )
        self.assertEqual(allowed.interval_seconds, 12)

        with self.assertRaises(ValidationError):
            MailImapConnectRequest(
                host="imap.gmail.com",
                username="you@gmail.com",
                password="abcdefghijklmnop",
                interval_seconds=2,
            )

    def test_connect_returns_before_inbox_poll(self) -> None:
        monitor = MailInboxMonitor()
        fake = FakeImap("imap.gmail.com", IMAP_TIMEOUT_SECONDS)
        with (
            patch("app.mail_guard._open_imap", return_value=fake),
            patch.object(MailInboxMonitor, "_loop", lambda self: None),
        ):
            status = monitor.connect(
                host="imap.gmail.com",
                username="demo@gmail.com",
                password="abcd efgh ijkl mnop",
                persist=False,
            )
            try:
                self.assertTrue(status["enabled"])
                self.assertEqual(status["username"], "demo@gmail.com")
                self.assertIn("Connected", status["last_message"])
                self.assertIsNone(status.get("password"))
                stopped = monitor.stop()
                self.assertFalse(stopped["enabled"])
            finally:
                monitor.stop()


if __name__ == "__main__":
    unittest.main()
