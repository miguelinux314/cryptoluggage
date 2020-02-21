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
import cryptography

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptoluggage
from cryptoluggage import Luggage


class TestCreation(unittest.TestCase):

    def test_creation_ok(self):
        """Test creation is performed well for various password lengths
        """
        for password_length in [0, 1, 32, 1024]:
            password = ''.join(random.choices(string.printable, k=password_length))

            tmp_id, tmp_path = tempfile.mkstemp()

            try:
                l1 = Luggage.create_new(target_path=tmp_path,
                                        master_password=password)
                l1.secrets[''.join(random.choices(string.printable, k=random.randint(1, 1000)))] = \
                    ''.join(random.choices(string.printable, k=random.randint(0, 1000)))

                # Check concurrency control
                try:
                    Luggage(tmp_path, password=password)
                    raise Exception(f"The luggage at {tmp_path} should not have been opened "
                                    f"(concurrency)")
                except cryptoluggage.LuggageInUseError:
                    pass

                # Check bad password control
                l1.close()
                if password_length > 0:
                    bad_password = password
                    while bad_password == password:
                        bad_password = ''.join(random.choices(string.printable, k=password_length))
                else:
                    bad_password = ''.join(random.choices(string.printable, k=random.randint(1, 2048)))
                try:
                    with Luggage(tmp_path, password=bad_password) as l:
                        l.secrets
                    raise Exception(f"Luggage was opened with a bad password?? (equal={password == bad_password})")
                except cryptoluggage.luggage.BadPasswordOrCorrupted:
                    pass

                l2 = Luggage(tmp_path, password=password)
                assert l1.secrets == l2.secrets

            finally:
                os.remove(tmp_path)

    def test_concurrency_control(self):
        pass
        # raise NotImplementedError()

        # cl = Luggage(luggage_path=tmp_luggage.name, password="meh")
        # #
        # print("[watch] cl.secrets = {}".format(cl.secrets))
        # cl.secrets["miguel"] = "cool"
        # print("[watch] cl.secrets = {}".format(cl.secrets))
        # cl.secrets["miguel2"] = "cool2"
        # print("[watch] cl.secrets = {}".format(cl.secrets))

        # cl.add_secret(s)

        # cl.create_new_db()

        # Luggage.create_new(target_path=options.luggage, master_password="meh")
        # secret = model.Secret()
        # f = model.Node(name="empty", parent=None)


if __name__ == '__main__':
    unittest.main()