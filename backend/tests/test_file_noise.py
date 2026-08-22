"""Do not treat this project's own README or Windows SMB as ransomware."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.file_guard import evaluate_path
from app.network_scanner import _connection_findings


class ProjectDocSkipTests(unittest.TestCase):
    def test_readme_md_is_not_malware(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "README.md"
            path.write_text(
                "CYBER_SENTINEL.AI classifies virus worm trojan ransomware malware",
                encoding="utf-8",
            )
            verdict = evaluate_path(path)
            self.assertFalse(verdict.malicious)
            self.assertEqual(verdict.threat_type, "benign")

    def test_decrypt_note_still_flags(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "README_FOR_DECRYPT.txt"
            path.write_text("Your files have been encrypted. Pay bitcoin wallet.", encoding="utf-8")
            verdict = evaluate_path(path)
            self.assertTrue(verdict.malicious)
            self.assertEqual(verdict.threat_type, "ransomware")


class LocalSmbSkipTests(unittest.TestCase):
    def test_local_smb_listener_is_not_emitted(self) -> None:
        listen = MagicMock()
        listen.laddr.port = 445
        listen.laddr.ip = "0.0.0.0"
        listen.raddr = None
        listen.status = "LISTEN"
        with patch("app.network_scanner.psutil") as fake:
            fake.CONN_LISTEN = "LISTEN"
            fake.CONN_ESTABLISHED = "ESTABLISHED"
            fake.net_connections.return_value = [listen]
            findings = _connection_findings("10.87.54.124")
        self.assertFalse(
            any("port 445" in (item.raw_payload or "") for item in findings)
        )


if __name__ == "__main__":
    unittest.main()
