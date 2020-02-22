#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for the encrypted file system
"""

import sys
import os
import unittest
import random
import string
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptoluggage import Luggage


class TestFS(unittest.TestCase):
    test_password = ''.join(random.choices(
        string.printable, k=random.randint(0, 10240)))

    def test_file_path_insertion(self):
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                    l.encrypted_fs[path] = __file__

            with Luggage(path=tmp_path, passphrase=self.test_password) as l2:
                for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                    with open(__file__, "rb") as f:
                        assert l2.encrypted_fs[path] == f.read()

                assert set(l2.encrypted_fs["a"].root.children.keys()) == set(("b", "c", "d"))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_open_file_insertion(self):
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            l = Luggage.create_new(path=tmp_path, passphrase=self.test_password)
            for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                with open(__file__, "rb") as f:
                    l.encrypted_fs[path] = f

            for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                with open(__file__, "rb") as f:
                    assert l.encrypted_fs[path] == f.read()

            assert set(l.encrypted_fs["a"].root.children.keys()) == set(("b", "c", "d"))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_subdir_operations(self):
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                l.encrypted_fs["/a/b/c.txt"] = __file__

            with Luggage(path=tmp_path, passphrase=self.test_password) as l2:
                with open(__file__, "rb") as f:
                    a = l2.encrypted_fs["/a"]
                    assert a["/b/c.txt"] == f.read()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_delete(self):
        """Test deletion of files and directories
        """
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                assert len(l) == 3
                l.encrypted_fs["/a/b/c.txt"] = __file__
                assert len(l) == 4

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                assert len(l) == 4
                del l.encrypted_fs["/a/b/c.txt"]
                assert len(l) == 3

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                assert len(l) == 3
                try:
                    l.encrypted_fs["/a/b/c.txt"]
                    raise Exception("l.encrypted_fs['/a/b/c.txt'] should have raised exception. "
                                    f"{l.encrypted_fs['/a/b/c.txt']} instead")
                except KeyError:
                    pass

                with open(__file__, "rb") as f:
                    l.encrypted_fs["/a/x/y1/z1.txt"] = f
                with open(__file__, "rb") as f:
                    l.encrypted_fs["/a/x/y1/z2.txt"] = f
                with open(__file__, "rb") as f:
                    l.encrypted_fs["/a/x/y2/z1.txt"] = f
                with open(__file__, "rb") as f:
                    l.encrypted_fs["/a/x/y2/z2.txt"] = f

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                assert len(l) == 7
                with open(__file__, "rb") as f:
                    assert l.encrypted_fs["/a/x/y2/z1.txt"] == f.read()
                del l.encrypted_fs["/a/x/y1"]

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                assert len(l) == 5
                for p in ["/a/x/y1/z1.txt", "/a/x/y1/z2.txt", "/a/x/y1"]:
                    try:
                        l.encrypted_fs[p]
                        raise Exception(f"{p} should have raised an exception")
                    except KeyError:
                        pass


        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == '__main__':
    unittest.main(failfast=True)
