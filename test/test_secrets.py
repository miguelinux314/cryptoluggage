#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for secret handling
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSecrets(unittest.TestCase):
    def test_secret_insertion(self):
        pass


if __name__ == '__main__':
    unittest.main()
