#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run all unit tests
"""

import os
import unittest
import datetime
import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose?")
    options = parser.parse_args()

    suite = unittest.TestLoader().discover(os.path.dirname(__file__))

    if options.verbose:
        print(f"Running {suite.countTestCases()} tests @ {datetime.datetime.now()}")
        print(f"{'[Params]':-^30s}")
        for param, value in options.__dict__.items():
            print(f"{param}: {value}")
        print(f"{'':-^30s}")
        print()

    unittest.TextTestRunner(verbosity=3 if options.verbose else 1).run(suite)
