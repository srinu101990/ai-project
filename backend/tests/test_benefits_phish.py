"""HR-benefits lures from a personal Gmail must classify as phishing."""

from __future__ import annotations

import unittest

from app.mail_guard import evaluate_mail


class BenefitsPhishTests(unittest.TestCase):
    def test_health_benefits_gmail_is_phishing(self) -> None:
        verdict = evaluate_mail(
            sender="Akash More <moreakash920@gmail.com>",
            subject="Action Required: Mandatory 2026 Employee Health Benefits Election",
            body=(
                "Hello Team,\n\n"
                "Please review the updated 2026 health insurance policy guidelines. "
                "All employees must re-enroll or confirm existing benefits packages "
                "to avoid a lapse in medical coverage for the upcoming quarter.\n\n"
                "The deadline for submission is this Friday at 5:00 PM EST."
            ),
        )
        self.assertTrue(verdict.phishing)
        self.assertEqual(verdict.threat_type, "phishing")
        self.assertEqual(verdict.verdict, "PHISHING DETECTED")

    def test_normal_work_mail_stays_safe(self) -> None:
        verdict = evaluate_mail(
            sender="noreply@company.com",
            subject="Weekly project notes",
            body="Hi team, the weekly notes are in the shared drive. See you tomorrow.",
        )
        self.assertFalse(verdict.phishing)
        self.assertEqual(verdict.threat_type, "benign")


if __name__ == "__main__":
    unittest.main()
