#!/usr/bin/env python3
"""Pin the Find My advertisement wire format.

A wrong byte here fails silently: the laptop advertises, iPhones report it, and
every report decrypts to garbage under our key. There is no error to notice, so
the encoding is checked against a vector produced by upstream OpenHaystack's own
Firmware/Linux_HCI/HCI.py.
"""

import base64
import hashlib
import sys
import unittest

from findmylinux import advertisement, derive_keypair, format_addr

UPSTREAM_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b")
UPSTREAM_ADDR = bytes.fromhex("c00102030405")
UPSTREAM_PAYLOAD = bytes.fromhex(
    "1eff4c00121900060708090a0b0c0d0e0f101112131415161718191a1b0000"
)


class TestAdvertisement(unittest.TestCase):
    def test_matches_upstream_vector(self):
        addr, payload = advertisement(UPSTREAM_KEY)
        self.assertEqual(addr, UPSTREAM_ADDR)
        self.assertEqual(payload, UPSTREAM_PAYLOAD)

    def test_payload_fills_one_advertisement(self):
        _, payload = advertisement(UPSTREAM_KEY)
        self.assertEqual(len(payload), 31)
        self.assertEqual(payload[0], len(payload) - 1)

    def test_address_is_static_random(self):
        for _ in range(200):
            _, key = derive_keypair()
            addr, _ = advertisement(key)
            self.assertEqual(addr[0] >> 6, 0b11)

    def test_whole_key_is_recoverable(self):
        """A receiver must be able to rebuild all 28 bytes from address+payload."""
        for _ in range(200):
            _, key = derive_keypair()
            addr, payload = advertisement(key)
            recovered = bytes([(addr[0] & 0b00111111) | (payload[29] << 6)])
            recovered += addr[1:6] + payload[7:29]
            self.assertEqual(recovered, key)


class TestKeys(unittest.TestCase):
    def test_keypair_shape(self):
        priv, adv = derive_keypair()
        self.assertEqual(len(priv), 28)
        self.assertEqual(len(adv), 28)

    def test_hashed_key_is_url_safe(self):
        """The hashed key becomes a URL path component in every report fetcher."""
        for _ in range(200):
            _, adv = derive_keypair()
            hashed = base64.b64encode(hashlib.sha256(adv).digest()).decode()
            self.assertNotIn("/", hashed[:7])

    def test_keys_are_distinct(self):
        keys = {derive_keypair()[0] for _ in range(50)}
        self.assertEqual(len(keys), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
