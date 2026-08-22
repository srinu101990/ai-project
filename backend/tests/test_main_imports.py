"""Guard rails so dashboard stats/PDF helpers stay imported."""

from __future__ import annotations

import unittest


class MainApiImportTests(unittest.TestCase):
    def test_report_helpers_are_wired(self) -> None:
        from app import main

        self.assertTrue(callable(main.get_stats))
        self.assertTrue(callable(main.build_report_summary))
        self.assertTrue(callable(main.generate_pdf_report))


if __name__ == "__main__":
    unittest.main()
