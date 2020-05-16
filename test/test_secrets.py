#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for secret handling
"""

import sys
import os
import unittest
import tempfile
import string
import random

random.seed(0xbadc0ff33)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptoluggage


class TestSecrets(unittest.TestCase):
    test_password = "".join(random.choices(string.printable, k=64))

    def test_secret_insertion(self):
        with tempfile.NamedTemporaryFile() as tmp_file:
            manual_key, manual_value = "test", "test\ncontents"

            expected_secrets = dict()
            with cryptoluggage.Luggage.create_new(path=tmp_file.name, passphrase=self.test_password) as l1:
                assert len(l1.secrets) == 0
                l1.secrets[manual_key] = manual_value
                expected_secrets[manual_key] = manual_value
                assert len(l1.secrets) == 1

            insertion_lengths = range(1, 2048, 47)
            with cryptoluggage.Luggage(path=tmp_file.name, passphrase=self.test_password) as l2:
                assert len(l2.secrets) == 1
                assert l2.secrets[manual_key] == manual_value

                for i, length in enumerate(insertion_lengths):
                    k = "".join(random.choices(string.printable, k=length))
                    v = "\n".join("".join(random.choices(string.printable, k=length)) for _ in range(1, length + 1))
                    assert k not in expected_secrets

                    expected_secrets[k] = v
                    l2.secrets[k] = v
                assert len(l2.secrets) == len(insertion_lengths) + 1

            with cryptoluggage.Luggage(path=tmp_file.name, passphrase=self.test_password) as l3:
                for k, v in expected_secrets.items():
                    assert l3.secrets[k] == v
                for k,v in l3.secrets.items():
                    assert expected_secrets[k] == v


if __name__ == '__main__':
    unittest.main()
