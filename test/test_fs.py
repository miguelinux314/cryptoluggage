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
import filecmp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptoluggage import Luggage


class TestFS(unittest.TestCase):
    test_password = ''.join(random.choices(
        string.printable, k=random.randint(0, 10240)))

    def test_file_path_insertion(self):
        """Test file insertions from paths
        """
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                    assert path not in l.encrypted_fs
                    l.encrypted_fs[path] = __file__
                    assert path in l.encrypted_fs

            with Luggage(path=tmp_path, passphrase=self.test_password) as l2:
                for path in ("/a/b/c/d.txt", "/a/c/c/d.txt", "/a/d/c/d.txt"):
                    with open(__file__, "rb") as f:
                        assert l2.encrypted_fs[path] == f.read()

                assert set(l2.encrypted_fs["a"].root.children.keys()) == set(("b", "c", "d"))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_open_file_insertion(self):
        """Test file insertion from open files
        """
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
        """Test subdirs provide similar functionality as the root
        """
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                l.encrypted_fs["/a/b/c.txt"] = __file__

            with Luggage(path=tmp_path, passphrase=self.test_password) as l2:
                with open(__file__, "rb") as f:
                    a = l2.encrypted_fs["/a"]
                    assert "b" in a
                    assert "b/c.txt" in a
                    assert a["/b/c.txt"] == f.read()
                    del a["/b"]

            with Luggage(path=tmp_path, passphrase=self.test_password) as l3:
                a = l3.encrypted_fs["a"]
                assert "b" not in a
                assert "b/c.txt" not in a

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_folder_insertion(self):
        with open(__file__, "rb") as this_file:
            this_file_contents = this_file.read()

        with tempfile.TemporaryDirectory() as tmp_dir:
            base_dir = os.path.join(tmp_dir, "base_dir")
            os.makedirs(base_dir)
            dirs_level_1 = ["A", "B", "C"]
            dirs_level_2 = ["a", "b"]
            files_level_2 = ["f1", "f2"]
            for dir_level_1 in dirs_level_1:
                os.makedirs(os.path.join(base_dir, dir_level_1))
            for dir_level_2 in dirs_level_2:
                os.makedirs(os.path.join(base_dir, dirs_level_1[0], dir_level_2))
            for file_name in files_level_2:
                with open(os.path.join(base_dir, dirs_level_1[0], file_name), "wb") as out_file:
                    out_file.write(this_file_contents)

            luggage_path = os.path.join(tmp_dir, "luggage.lug")
            passphrase = "".join(random.choices(string.printable, k=5012))
            with Luggage.create_new(path=luggage_path, passphrase=passphrase) as l1:
                l1.encrypted_fs["/base_dir"] = os.path.join(tmp_dir, "base_dir")

            output_path = os.path.join(tmp_dir, "reconstructed")
            with Luggage(path=luggage_path, passphrase=passphrase) as l2:
                l2.encrypted_fs.export(virtual_path="/base_dir", output_path=output_path)

            dcmp = filecmp.dircmp(base_dir,
                                  os.path.join(tmp_dir, "reconstructed", "base_dir"))
            assert len(dcmp.left_only) == 0, dcmp.left_only
            assert len(dcmp.right_only) == 0, dcmp.right_only
            assert len(dcmp.diff_files) == 0, dcmp.diff_files

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
                assert len(l) == 4, len(l)
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
                    read = l.encrypted_fs["/a/x/y2/z1.txt"]
                    expected = f.read()
                    assert read == expected
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

    def test_path_formation(self):
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            paths = ["/a.txt", "a/b.txt", "a/c/d.txt"]
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                for p in paths:
                    l.encrypted_fs[p] = __file__

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                generated_paths = [f.path for f in l.encrypted_fs.root.get_descendents(get_dirs=False, get_files=True)]
                generated_paths = [p[1:] if p.startswith("/") else p for p in generated_paths]
                paths = [p[1:] if p.startswith("/") else p for p in paths]
                assert set(generated_paths) == set(paths), (set(generated_paths), set(paths))

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_iteration(self):
        tmp_id, tmp_path = tempfile.mkstemp()
        try:
            paths = ["/a/a.txt", "a/b.txt", "a/c.txt", "a/d.txt", "a/e.txt"]
            with Luggage.create_new(path=tmp_path, passphrase=self.test_password) as l:
                for p in paths:
                    l.encrypted_fs[p] = __file__

            with Luggage(path=tmp_path, passphrase=self.test_password) as l:
                found_paths = []
                for p in l.encrypted_fs["a"]:
                    found_paths.append(p.name)
            assert sorted(found_paths) == sorted(os.path.basename(p) for p in paths)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == '__main__':
    unittest.main(failfast=True)
