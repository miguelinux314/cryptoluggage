#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests to check whether luggages can be correctly created and opened
"""

import sys
import os
import unittest
import tempfile
import string
import random
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptoluggage
from cryptoluggage import Luggage


class TestCreation(unittest.TestCase):

    def test_creation_ok(self):
        """Test whether creation is performed well for various password lengths
        """
        for password_length in [0, 1, 32, 1024]:
            password = ''.join(random.choices(string.printable, k=password_length))

            tmp_id, tmp_path = tempfile.mkstemp()

            try:
                l1 = Luggage.create_new(path=tmp_path, passphrase=password)
                # Check bad password control
                l1.close()
                assert not os.path.exists(l1.lock_path)

                if password_length > 0:
                    bad_password = password
                    while bad_password == password:
                        bad_password = ''.join(random.choices(string.printable, k=password_length))
                else:
                    bad_password = ''.join(random.choices(string.printable, k=random.randint(1, 2048)))
                try:
                    with Luggage(tmp_path, passphrase=bad_password) as l:
                        l.secrets
                        l.close()
                    assert not os.path.exists(l.lock_path)
                    raise Exception(f"Luggage was opened with a bad password?? (equal={password == bad_password})")
                except cryptoluggage.luggage.BadPasswordOrCorruptedException:
                    pass

                assert not os.path.exists(l1.lock_path)

                l2 = Luggage(tmp_path, passphrase=password)
                l2.close()
            finally:
                os.remove(tmp_path)

    def test_concurrency_control(self):
        for password_length in [0, 1, 32, 1024]:
            password = ''.join(random.choices(string.printable, k=password_length))

            tmp_id, tmp_path = tempfile.mkstemp()

            try:
                l1 = Luggage.create_new(path=tmp_path,
                                        passphrase=password)
                # Check concurrency control
                try:
                    Luggage(tmp_path, passphrase=password)
                    raise Exception(f"The luggage at {tmp_path} should not have been opened "
                                    f"(concurrency)")
                except cryptoluggage.LuggageInUseError:
                    pass
            finally:
                os.remove(tmp_path)


if __name__ == '__main__':
    unittest.main()
