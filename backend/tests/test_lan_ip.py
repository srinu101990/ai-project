"""Prefer a phone-hotspot IPv4 over a leftover campus 10.x address."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from app.network_scanner import preferred_lan_ip


class PreferredLanIpTests(unittest.TestCase):
    def test_iphone_hotspot_beats_campus_wifi(self) -> None:
        with patch(
            "app.network_scanner.list_local_ipv4s",
            return_value=["10.87.54.124", "172.20.10.5"],
        ), patch("app.network_scanner._route_ipv4", return_value="10.87.54.124"):
            self.assertEqual(preferred_lan_ip(), "172.20.10.5")

    def test_android_hotspot_beats_campus_wifi(self) -> None:
        with patch(
            "app.network_scanner.list_local_ipv4s",
            return_value=["10.87.54.124", "192.168.43.12"],
        ), patch("app.network_scanner._route_ipv4", return_value="10.87.54.124"):
            self.assertEqual(preferred_lan_ip(), "192.168.43.12")

    def test_falls_back_to_route_ip(self) -> None:
        with patch("app.network_scanner.list_local_ipv4s", return_value=["10.87.54.124"]), patch(
            "app.network_scanner._route_ipv4", return_value="10.87.54.124"
        ):
            self.assertEqual(preferred_lan_ip(), "10.87.54.124")


if __name__ == "__main__":
    unittest.main()
