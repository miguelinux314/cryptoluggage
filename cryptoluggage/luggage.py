#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptoluggage for python 3

"""
__author__ = "Miguel Hernández Cabronero <miguel.hernandez@uab.cat>"
__date__ = "08/02/2020"

import json
import os
import fnmatch
import base64
import sqlite3
import pickle
import sys
import time
import struct
import filelock
import sortedcontainers
import string
import io
# Cryptography specific imports
import cryptography.fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from . import model


class RepeatedNameError(Exception):
    """Raised when a repeated name is repeated, and that is not allowed.
    """
    pass


class BadPathException(Exception):
    """Raised when a path is not correct.
    """
    pass


class OverwriteRefuseError(Exception):
    """Raised when an insertion is refused because it would overwrite
    an existing file."""

    def __init__(self, name, path):
        super().__init__(f"Insertion of '{name}' into '{path}' refused: "
                         f"a file or directory with that name already exists.")
        self.name, self.path = name, path


class LuggageInUseError(Exception):
    """A luggage is being accessed, but it is already being
    open by another instance.
    """
    pass


class LuggageClosedError(Exception):
    """A luggage was used after being closed
    """


class BadPasswordOrCorruptedException(Exception):
    """Attempted opening a luggage with the wrong password, or the file is
    corrupted.
    """
    pass


class LuggageFernet(cryptography.fernet.Fernet):
    """Adaptation of cryptography's Fernet tweaked for privacy,
     compactness and speed (no going back and forth to and from base64)
     """

    def encrypt_binary(self, data, erase_time=True):
        """Encrypt data and return bytes, without converting to Base64.
        """
        current_time = time.time() if not erase_time else 0
        iv = os.urandom(16)
        return self._encrypt_from_parts_no_base64(data, current_time, iv)

    def decrypt_binary(self, token):
        """Decrypt bytes and return the compressed data as a string
        """
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        # (No base64 decryption)
        data = token
        if not data or data[0] != 0x80:
            raise BadPasswordOrCorruptedException()

        h = HMAC(self._signing_key, hashes.SHA256())

        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise BadPasswordOrCorruptedException()

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise BadPasswordOrCorruptedException()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise BadPasswordOrCorruptedException()
        return unpadded

    @classmethod
    def key_from_password(cls, password: str, luggage_params: "LuggageParams") -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=luggage_params.master_key_salt,
            iterations=luggage_params.master_key_iterations,
            backend=default_backend())
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    def _encrypt_from_parts_no_base64(self, data, current_time, iv):
        """Copy-and-paste from from fernet.Fernet, save for the return
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
                b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256())
        h.update(basic_parts)
        hmac = h.finalize()

        return basic_parts + hmac


class LuggageParams:
    """Parameters employed in a Luggage
    """
    default_salt_legth_bytes = 24

    def __init__(self, master_key_salt=None, master_key_iterations=1000000):
        """
        :param master_key_salt: salt used for deriving the master key. If none, os.urandom is called
        :param master_key_iterations: number of iterations used to derive the master key from a password
        """
        self.master_key_salt = os.urandom(self.default_salt_legth_bytes) if master_key_salt is None else master_key_salt
        assert master_key_iterations > 0
        self.master_key_iterations = int(master_key_iterations)

    def dumps(self) -> str:
        """Return a serialized, plain-text version of the parameters.
        """
        return json.dumps({
            # Convert the byte string (salt) to a Base64-encoded text string
            "master_key_salt": base64.b64encode(self.master_key_salt).decode("utf-8"),
            "master_key_iterations": self.master_key_iterations,
        }).encode("utf-8")

    @staticmethod
    def loads(s: str, legacy: bool = False) -> "LuggageParams":
        """Return a LuggageParams instance from a serialized output produced by dumps().
        :param s: serialized parameter string as stored in the Luggage database.
        :param legacy: if True, the string is unpickled instead of json-decoded (unsafe for tampered
            Luggages, but required for Luggages created with cryptoluggage < 3.1.0)."""

        if not legacy:
            try:
                param_dict = json.loads(s)
            except (UnicodeDecodeError, json.JSONDecodeError) as ex:
                print("There was an error decoding the Luggage parameters. "
                      "If you are opening a Luggage created with version < 3.1.0, "
                      "and you are ENTIRELY SURE the Luggage file has not been tampered with, "
                      f"run again the open command with the --legacy option.\n\n\tDebug info: {ex}.")
                sys.exit(1)
            params = LuggageParams(
                master_key_salt=base64.b64decode(param_dict["master_key_salt"]),
                master_key_iterations=param_dict["master_key_iterations"],
            )
        else:
            params = pickle.loads(s)

        return params


class SecretsDict(sortedcontainers.SortedDict):
    def __init__(self, luggage, *args, **kwargs):
        self.luggage = luggage
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.write_to_db(commit=True)

    def __delitem__(self, key):
        super().__delitem__(key)
        self.write_to_db(commit=True)

    def write_to_db(self, commit=True):
        self.luggage.db_conn.cursor().execute(
            "REPLACE INTO token_store (id, token) VALUES (?, ?)",
            (self.luggage.secrets_id,
             self.luggage.master_fernet.encrypt_binary(
                 self.dumps())))
        if commit:
            self.luggage.db_conn.commit()

    def dumps(self):
        return pickle.dumps(dict(self))

    @staticmethod
    def read_from_db(luggage):
        """Read the secrets dict from the luggage's encrypted database.
        Also update luggage._secrets."""
        try:
            cursor = luggage.db_conn.cursor()
        except AttributeError as ex:
            if luggage.db_conn is None:
                raise LuggageClosedError()
            else:
                raise ex

        # Load encrypted secrets
        for secrets_token, in cursor.execute(r"SELECT token FROM token_store"
                                             f" WHERE id={luggage.secrets_id:d}"):
            luggage._secrets = SecretsDict(luggage=luggage)
            decrypted = luggage.master_fernet.decrypt_binary(secrets_token)
            # Only allow dicts to be loaded
            secrets_dict = restricted_loads(decrypted)
            if not isinstance(secrets_dict, dict):
                raise pickle.UnpicklingError("Loaded secrets is not a dict")
            luggage._secrets.update(secrets_dict)
            return luggage._secrets
        else:
            raise ValueError(f"Could not find parameter entry "
                             f"id#{luggage.secrets_id}. Corrupted Luggage?")


class EncryptedFS(model.Dir):
    """Provide access to the encrypted filesystem of a Luggage
    """

    def __init__(self, luggage: "Luggage", root: model.Dir = None):
        """
        :param luggage: open luggage
        :param root: root directory for this EncryptedFS
        """
        self.luggage = luggage
        cursor = self.luggage.db_conn.cursor()
        if root is None:
            for root_node_token, in cursor.execute(r"SELECT token FROM token_store"
                                                   f" WHERE id={self.luggage.root_folder_id:d}"):
                decrypted = self.luggage.master_fernet.decrypt_binary(root_node_token)
                root_obj = restricted_loads(decrypted)
                if not isinstance(root_obj, model.Dir):
                    raise pickle.UnpicklingError("Loaded root is not a Dir")
                self.root = root_obj
                break
            else:
                raise BadPasswordOrCorruptedException(f"Could not find parameter entry id{self.secrets_id}.")
        else:
            self.root = root

    @property
    def children(self):
        return self.root.children

    @property
    def name(self):
        return self.root.name

    @name.setter
    def name(self, new_value):
        self.root.name = new_value

    @property
    def parent(self):
        return self.root.parent

    @parent.setter
    def parent(self, new_value):
        self.root.parent = new_value

    def insert_disk_file(self, virtual_path, file_or_path, cursor=None):
        """Insert a file from disk into the luggage's encrypted filesystem.

        :param virtual_path: a str-like object that points to a file in the Luggage's
          virtual (encrypted) filesystem or an existing dir. Example paths are:
                /a.txt
                a.txt
          A file named a.txt at the luggage's root.
                /a/b/c.bin
                a/b/c.bin
          file named c.bin under b; b is a subdir of a;
          a is a subdir of the luggage's root.
        :param value: a str-like object with the input file's path, or an open file-like
            object that can be read()
        :param cursor: if None, a cursor is created from the current connection
          to the db, and changes are commited after insertion. If not None,
          this cursor is used and changes are NOT commited.
        """
        target_dir, target_name = self.get_target_dir_and_name(
            target_path=virtual_path, source_file_or_path=file_or_path)

        # Delete previous file if existing
        if target_name in target_dir.children:
            raise OverwriteRefuseError(
                target_name,
                os.path.join(target_dir.path, target_name))

        # Get file contents
        try:
            with open(file_or_path, "rb") as f:
                contents = f.read()
        except (TypeError, FileNotFoundError):
            try:
                contents = file_or_path.read()
            except AttributeError:
                if os.path.islink(file_or_path) and not os.path.exists(file_or_path):
                    print(f"Warning: found broken link {file_or_path!r} "
                          f"-> {os.path.realpath(file_or_path)!r}. Skipping.")
                    return
                else:
                    raise ValueError(f"right value of type {type(file_or_path)} not valid")
        except PermissionError:
            raise BadPathException(f"The target path {file_or_path!r} cannot be read due to permission errors.")
        assert contents is not None

        # Store new token
        file_cursor = self.luggage.db_conn.cursor() if cursor is None else cursor
        file_cursor.execute(r"INSERT INTO token_store (token) VALUES (?)",
                            (self.luggage.master_fernet.encrypt_binary(data=contents),))
        new_file = model.File(name=target_name, parent=target_dir, token_id=file_cursor.lastrowid)
        target_dir.children[new_file.name] = new_file
        self._replace_root_dumps(cursor=file_cursor, commit=cursor is None)

    def get_target_dir_and_name(self, target_path, source_file_or_path, create=True):
        """
        Given a target virtual path and a path or file-like objects,
        verify that they are valid (raises BadPathException otherwise),
        and return the :class:`model.Dir` where a file can be stored,
        and the name that file should have (target_path can point to a directory,
        and in that case source_file_or_path must be a path (otherwise a BadPathException is rised).
        :param target_path: a path within the luggage. It can point to existing files (its dir and name are returned),
          or to existing dirs. If it points to a dir, it is verified that that dir does not have a subfolder
          with the same name as source_file_or_path. If verification passes, the dir pointed at becomes
          the one being returned.
        :param source_file_or_path: a path to a disk file (existence not checked), or an open file-like object.
          If an open file is passed as argument, target path must point to a file or a BadPathException is risen.
        :param create: if True, parent folder are created as needed
        :return: target_dir, target_name; where target_dir is a :class:`model.Dir` instance
          and target_name is the name that should be used for the contents of insert source_file_or_path
        """
        # Initially assume that target_path points to a file in the luggage   
        virtual_parent_names, target_name = self.split_path(target_path)

        # If the target_path is the root, the target_dir and name are trivial
        if not target_name:
            return self.root, os.path.basename(source_file_or_path)

        # Initially set target dir to the parent of target_path (creating if necessary)
        target_dir = self.dir_from_parents(parent_names=virtual_parent_names, create=create)

        # If the target_path is an existing dir, set that to the target_dir but make the target_name 
        # The name of the source file or path
        try:
            if target_name in target_dir.children:
                target_dir = target_dir.children[target_name]
                target_name = os.path.basename(source_file_or_path)
        except AttributeError:
            # It is not a dir, no modification is needed
            raise OverwriteRefuseError(target_dir.name, target_dir.path)

        # Ensure the destination is a dir
        try:
            _ = target_dir.children
        except AttributeError:
            raise OverwriteRefuseError(target_dir.name, target_dir.path)

        return target_dir, target_name

    def insert_disk_dir(self, virtual_path, dir_path):
        """Recursively insert an external directory into the luggage.
        """
        dir_path = os.path.abspath(dir_path)

        for dirpath, _, filenames in os.walk(dir_path, followlinks=True):
            dirpath = os.path.abspath(dirpath)
            target_dir_path = os.path.join(
                os.sep, virtual_path,
                dirpath.replace(os.path.dirname(os.path.abspath(dir_path)) + os.sep, ""))

            for file_name in filenames:
                target_file_path = os.path.join(target_dir_path, file_name)
                self.insert_disk_file(
                    virtual_path=target_file_path,
                    file_or_path=os.path.join(dirpath, file_name))
            if not filenames:
                # Make sure that dirs without files are also created
                _ = self.dir_from_path(virtual_path=target_dir_path, create=True)
        self._replace_root_dumps(cursor=self.luggage.db_conn.cursor(), commit=True)

    def export(self, virtual_path, output_path):
        output_path = os.path.realpath(os.path.expanduser(output_path))
        while virtual_path and virtual_path[0] == os.sep:
            virtual_path = virtual_path[1:]
        print(f"Exporting {virtual_path} into {output_path}...")
        try:
            contents = self[virtual_path]
            if hasattr(contents, "children"):
                # Export a dir
                if os.path.isfile(output_path):
                    raise ValueError(f"Cannot export directory {virtual_path} to existing file {output_path}")
                else:
                    output_path = os.path.join(output_path, os.path.basename(virtual_path))
                    os.makedirs(output_path, exist_ok=True)

                os.makedirs(output_path, exist_ok=True)
                remaining_elements = list(contents.children.values())
                while remaining_elements:
                    current_element = remaining_elements.pop()
                    current_path = current_element.path.replace(virtual_path, "")
                    while current_path and current_path[0] == os.sep:
                        current_path = current_path[1:]
                    try:
                        for child in current_element.children.values():
                            remaining_elements.append(child)
                        target = os.path.join(output_path, current_path)
                        os.makedirs(target, exist_ok=True)
                    except AttributeError:
                        target = os.path.join(output_path, current_path)
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        with open(target, "wb") as output_file:
                            output_file.write(self[current_element.path])
            else:
                # Export a file
                if not os.path.exists(output_path) or os.path.isfile(output_path):
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)
                    with open(output_path, "wb") as output_file:
                        output_file.write(contents)
                elif os.path.isdir(output_path):
                    with open(os.path.join(output_path, os.path.basename(virtual_path)), "wb") as output_file:
                        output_file.write(contents)
                else:
                    raise RuntimeError(f"Unexpected situation {virtual_path} -> {output_path}")

        except KeyError:
            raise BadPathException(f"Virtual path {virtual_path} does not exist.")

    def move(self, source_path, target_path):
        """Move source into target, creating target's parents recursively if necessary.
        source_path must exist prior to this call. Target path will be overwritten if both source and target
        are files. If target_path is an existing dir, source is simply moved into it.
        """
        source_node = self.get_node(virtual_path=source_path)
        try:
            target_node = self.get_node(virtual_path=target_path)

            # Refuse to overwrite existing files and into its own subdirs
            try:
                _ = target_node.children
                if any(child == source_node.name for child in target_node.children):
                    raise OverwriteRefuseError(source_path, os.path.join(target_path, source_node.name))
                current_node = target_node
                while current_node.parent is not None:
                    if current_node.parent is source_node:
                        raise BadPathException(f"Cannot move {source_path!r} into its own subdirectory {target_path!r}")
                    current_node = current_node.parent
            except AttributeError:
                raise OverwriteRefuseError(source_path, target_path)

            if source_node is target_node:
                raise BadPathException(f"Cannot move {source_path} to itself")
            # Moving to an existing path
            try:
                # Moving into an existing dir
                if source_node.name in target_node.children:
                    if hasattr(target_node.children[source_node.name], "children"):
                        raise BadPathException(
                            f"Cannot move directory {source_path} into existing file {target_node.children[source_name]}")
                # source_node.parent.children[source_node.name]
                del source_node.parent.children[source_node.name]
                source_node.parent = target_node
                source_node.parent.children[source_node.name] = source_node
            except AttributeError:
                # Moving into an existing file
                if hasattr(source_node, "children"):
                    raise BadPathException(
                        f"Cannot move directory {source_path} into existing file {target_path}")
                del self[target_node.path]
                del source_node.parent.children[source_node.name]
                source_node.name = target_node.name
                source_node.parent = target_node.parent
                source_node.parent.children[source_node.name] = source_node
        except KeyError:
            # Moving into a new path;
            target_parents, target_name = self.split_path(virtual_path=target_path)
            target_node = self.dir_from_parents(parent_names=target_parents, create=True)
            del source_node.parent.children[source_node.name]
            target_name = target_name if target_name else source_node.name
            source_node.parent = target_node
            source_node.name = target_name
            source_node.parent.children[source_node.name] = source_node

        self._replace_root_dumps(cursor=self.luggage.db_conn.cursor(), commit=True)

    def get_node(self, virtual_path, load_contents=False):
        """Get the model.Node corresponding to a path, or raise KeyError if not found.
        (Note that both Files and Dirs can be returned).

        :param load_contents: if virtual_path exists and is a file, its contents
          are returned instead of the file node if load_contents is True
        """
        parent_names, file_name = self.split_path(virtual_path)
        if not parent_names and not file_name:
            return self

        target_dir = self.dir_from_parents(parent_names=parent_names, create=False)

        target_element = target_dir.children[file_name]
        try:
            target_element.children
        except AttributeError:
            if load_contents:
                cursor = self.luggage.db_conn.cursor()
                for token_data, in cursor.execute("SELECT token FROM token_store "
                                                  f"WHERE id={target_element.token_id:d}"):
                    return self.luggage.master_fernet.decrypt_binary(token_data)

        return target_element

    def dumps(self):
        """Return a pickled string that represents the root node of this encrypted
        filesystem. It does not contain encrypted data, only the filesystem structure
        and pointers to the token database.
        """
        return pickle.dumps(self.root)

    def split_path(self, virtual_path):
        """Split a virtual path into a list of parent names (first one, if present,
        is a subdirectory of the root), and file_name.
        No checks are made about number of parents of file_name contents
        :return: parent_name_list, file_name
        """
        # if any(c not in string.printable for c in virtual_path):
        #     raise ValueError(f"Virtual path '{virtual_path}' contains non-printable characters")
        parents, file_name = os.path.split(virtual_path)
        parent_names = []
        while parents and os.path.normpath(parents) != "/":
            parents, parent_name = os.path.split(os.path.normpath(parents))
            parent_names.append(parent_name)
        if not file_name and parent_names:
            file_name = parent_names[0]
            parent_names = parent_names[1:]

        return list(reversed(parent_names)), file_name

    def dir_from_path(self, virtual_path, create=True):
        """Get a directory corresponding to virtual_path. Note that the last
        element of virtual_path is assumed to be the name of the deepest
        directory.

        :param create: if True, parent directories are created as needed. Otherwise,
          a KeyError is raised.
        """
        parent_names, file_name = self.split_path(virtual_path=virtual_path)
        parent_names.append(file_name)
        return self.dir_from_parents(parent_names=parent_names, create=create)

    def dir_from_parents(self, parent_names, create=True):
        """Return the model.Dir instance pointed by a list of parent names,
        i.e., its path.

        :param create: if True, parent dirs are created as necessary.
          Otherwise, if any element before the last one does not exist
          in the luggage, a KeyError exception in raised.
        """
        target_dir = self.root
        for name in parent_names:
            try:
                target_dir = target_dir.children[name]
            except KeyError as ex:
                if create:
                    # Parent dir did not exist - create it
                    new_dir = model.Dir(name=name, parent=target_dir)
                    target_dir.children[name] = new_dir
                    target_dir = new_dir
                else:
                    raise ex
            if not hasattr(target_dir, "children"):
                raise BadPathException(f"{target_dir} is not a directory")
        return target_dir

    def print_node_list(self, filter_string=None):
        """Print a list of all nodes contained in the filesystem"""
        nodes = self.root.get_descendents(get_files=True, get_dirs=True)

        try:
            # Get and show the root
            _ = next(nodes)
            print(f"[{self.luggage.path}]")
        except StopIteration:
            raise RuntimeError(f"Error getting the root of the encrypted filesystem of {self.luggage.path}. "
                               f"Something is very wrong )-:")

        match_found = False
        for node in nodes:
            if filter_string is None or fnmatch.fnmatch(node.name.lower(), f"*{filter_string.lower()}*"):
                match_found = True
                print(node.path + ("" if not hasattr(node, "children") else "/"))
        if not match_found and filter_string is not None:
            print(f"No secret file found matching filter '{filter_string}'.")

    def print_tree(self, filter_string=None):
        """Print the filesystem hierarchy as a tree
        """
        self._print_node(node=self.root, level=0, filter_string=filter_string)

    def _print_node(self, node, level, filter_string=None):
        s = " " * (3 * (level - 1)) + (" +-" if level > 0 else "")

        relevant_subfolder = hasattr(node, "children") and \
                             (filter_string is None
                              or any(filter_string in d.name for d in node.get_all_descendents()))

        if node is not self.root or self.luggage.encrypted_fs.root is not self.root:
            if filter_string is None or filter_string in node.name or relevant_subfolder:
                if hasattr(node, "children"):
                    lbracket, rbracket = "[", "/]"
                else:
                    lbracket, rbracket = "--", " "
                print(s + f"{lbracket}{node.name}{rbracket}")
        else:
            print(f"[{self.luggage.path}]")
        try:
            if relevant_subfolder:
                for name, node in node.children.items():
                    # print(" " * (3 * (level)) + " |")
                    self._print_node(node=node, level=level + 1,
                                     filter_string=filter_string if filter_string != name else None)
        except AttributeError:
            pass

    def _replace_root_dumps(self, cursor, commit=False):
        cursor.execute(r"REPLACE INTO token_store (id, token) VALUES (?, ?)",
                       (self.luggage.root_folder_id,
                        self.luggage.master_fernet.encrypt_binary(
                            self.luggage.encrypted_fs.dumps())))
        if commit:
            self.luggage.db_conn.commit()

    def __getitem__(self, virtual_path):
        """Return an EncryptedFS instance if a dir is pointed to,
        or the contents of a file if a file is pointed to.
        :param virtual_path: path to the element to be retrieved
        :return: if virtual_path points to a folder, an EncryptedFS instance
          is returned. If it points to a file, the contents (bytes) of the
          file are returned.
        """
        node = self.get_node(virtual_path=virtual_path, load_contents=True)
        if isinstance(node, model.Dir):
            return EncryptedFS(luggage=self.luggage, root=node)
        return node

    def __setitem__(self, virtual_path, value):
        """Save a file or directory to the virtual path, creating parent dirs as necessary.
        Virtual path splitting is based on os.path. Virtual paths may optionally include a leading os.sep.
        If a directory is inserted, its contents are inserted recursively.

        :param virtual_path: a str-like object that points to a file in the Luggage's
          virtual (encrypted) filesystem. Example paths are:
                /a.txt
                a.txt
          A file named a.txt at the luggage's root.
                /a/b/c.bin
                a/b/c.bin
          file named c.bin under b; b is a subdir of a;
          a is a subdir of the luggage's root.
        :param value: either:
          - a str-like object pointing to a directory
          - a str-like object pointing to a file path
          - an open file-like object that can be read()
        """
        if hasattr(value, "read") or os.path.isfile(value):
            self.insert_disk_file(virtual_path=virtual_path, file_or_path=value)
        elif os.path.isdir(value):
            self.insert_disk_dir(virtual_path=virtual_path, dir_path=value)
        elif not os.path.exists(value):
            raise BadPathException(f"Path {value!r} does not exist on disk")
        else:
            raise ValueError(f"Invalid assignment ({value}). Must be an existing file, filepath or dirpath")

    def __delitem__(self, key):
        """Delete a file or a dir, recursively in the latter case
        """
        parent_names, name = self.split_path(key)
        target_dir = self.dir_from_parents(parent_names=parent_names, create=False)
        if not name:
            if target_dir is self.luggage.encrypted_fs.root:
                raise BadPathException("Cannot delete_node the root")
            target = target_dir
        else:
            target = target_dir.children[name]
        cursor = self.luggage.db_conn.cursor()
        try:
            # Assume it is a file
            cursor.execute(f"DELETE FROM token_store WHERE id={target.token_id:d}")
        except AttributeError:
            # It must be a directory
            for file in target.get_descendents(get_files=True, get_dirs=False):
                cursor.execute(f"DELETE FROM token_store WHERE id={file.token_id:d}")

        del target.parent.children[target.name]
        self._replace_root_dumps(cursor, commit=True)

    def __contains__(self, virtual_path):
        """
        :return: True if and only if virtual_path points to an existing element
        in the encrypted filesystem
        """
        parent_names, name = self.split_path(virtual_path)
        try:
            target_dir = self.dir_from_parents(parent_names=parent_names, create=False)
            return not name or name in target_dir.children
        except KeyError:
            return False

    def __iter__(self):
        return self.root.__iter__()

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.root)})"


class Luggage:
    """Luggage (encrypted database for secrets and files).
    """
    # Negative IDs are reserved for special entries. Non-negative IDs are for secret file contents.
    root_folder_id, secrets_id, params_id = range(-3, 0)

    def __init__(self, path: str, passphrase: str, legacy: bool = False):
        """Open a luggage for the given passphrase, generating a new one if it does not exist.
        :param path: path to the luggage file
        :param passphrase: master passphrasse for the luggage (utf8 string)
        :param legacy: if True, the Luggage parameters are open using pickle instead of json (unsafe for tampered
          Luggages, but needed for Luggages created with cryptoluggage < 3.1.0).
        """
        self.path = path
        try:
            if not os.path.exists(self.path):
                if legacy:
                    print("Creating a new Luggage with the legacy format is not supported.")
                    sys.exit(1)
                self.create_new(path=self.path,
                                passphrase=passphrase)
            self.db_conn, self.master_fernet = self._open(passphrase=passphrase, legacy=legacy)
            existed_before = os.path.exists(self.lock_path)
            self.lock = filelock.FileLock(lock_file=self.lock_path)
            self.lock.acquire(timeout=0.1)

            # Force reading of DB to password check
            _ = self.secrets

            # If opened in legacy mode, immediately save to upgrade to the new format
            if legacy:
                self._save_params(self.params, self.db_conn, db_cursor=None)
                print("The Luggage has been updated to use the non-legacy format. "
                      "You won't need to use the --legacy option again for this Luggage.")
        except filelock.Timeout as ex:
            if not existed_before:
                try:
                    os.remove(self.lock_path)
                except FileExistsError:
                    pass

            raise LuggageInUseError(
                f"The Luggage {self.path} seems to be already opened elsewhere.\n"
                f"If you are sure this is not the case, remove {self.lock_path} "
                "and try again") from ex
        except Exception as ex:
            if not existed_before:
                try:
                    os.remove(self.lock_path)
                except FileExistsError:
                    pass
            raise ex

    @classmethod
    def create_new(cls, path, passphrase: str) -> "Luggage":
        """Create a new Luggage (encrypted DB) at target_path for the given master password.
        :return: the newly created Luggage instance
        """
        if os.path.exists(path):
            print(f"Luggage file {path} already exists. I refuse to overwrite it. "
                  f"Delete manually if you want to proceed.")
            sys.exit(1)

        try:
            os.remove(path)
        except FileNotFoundError:
            pass

        conn = sqlite3.connect(path)
        c = conn.cursor()
        c.execute(r"CREATE TABLE token_store ("
                  r"    id INTEGER PRIMARY KEY, "
                  r"    token BLOB)")
        c.execute(r"CREATE UNIQUE INDEX index_token_store ON token_store (id)")

        # Parameters are public - no password
        luggage_params = LuggageParams()
        cls._save_params(luggage_params, db_conn=conn, db_cursor=c)

        # root and secrets are encrypted
        master_fernet = LuggageFernet(
            key=LuggageFernet.key_from_password(password=passphrase, luggage_params=luggage_params))
        secrets = {}
        empty_root = model.Dir(name="__root__")
        for db_id, instance in ((cls.root_folder_id, empty_root),
                                (cls.secrets_id, secrets)):
            c.execute(r"INSERT INTO token_store (id, token) VALUES (?, ?)",
                      (db_id, master_fernet.encrypt_binary(pickle.dumps(instance))))

        conn.commit()
        return Luggage(path=path, passphrase=passphrase)

    def change_passphrase(self, new_passphrase: str, params: LuggageParams = None):
        """Change the luggage's master passphrase to new_passphrase.
        :param new_passphrase: the new master passphrase
        :param params: if not None, use these luggage parameters for the new passphrase.
          Otherwise, the default parameters are used.
        """
        # Update the params
        if params is None:
            params = LuggageParams()
        self._save_params(luggage_params=params, db_conn=self.db_conn)

        old_master_fernet = self.master_fernet
        new_master_fernet = LuggageFernet(
            key=LuggageFernet.key_from_password(password=new_passphrase, luggage_params=params))

        # Re-encrypt all entries except for the params_id (which is stored in plain text)
        cursor = self.db_conn.cursor()
        ids = [row[0] for row in cursor.execute("SELECT id FROM token_store").fetchall()]
        for token_id in ids:
            if token_id == self.params_id:
                continue

            # Load existing blob
            cur = self.db_conn.cursor()
            cur.execute("SELECT token FROM token_store WHERE id=?", (token_id,))
            row = cur.fetchone()
            if row is None:
                continue
            old_blob = row[0]

            # Decrypt with old master fernet
            try:
                decrypted = old_master_fernet.decrypt_binary(old_blob)
            except Exception as ex:
                # If decryption fails, surface a clear error
                raise BadPasswordOrCorruptedException(f"Failed to decrypt token id {token_id}: {ex}")

            # Encrypt with the new master fernet
            new_blob = new_master_fernet.encrypt_binary(decrypted)

            # Update the token in the DB
            cursor.execute("UPDATE token_store SET token=? WHERE id=?", (new_blob, token_id))

        # Commit all updates and switch to the new master fernet
        self.db_conn.commit()
        self.master_fernet = new_master_fernet

    @property
    def secrets(self):
        try:
            return self._secrets
        except AttributeError:
            return SecretsDict.read_from_db(self)

    @property
    def encrypted_fs(self):
        """Get the encrypted file system's root node
        (reading it if not currently present)
        """
        try:
            return self._encrypted_fs
        except AttributeError:
            self._encrypted_fs = EncryptedFS(luggage=self)
            return self._encrypted_fs

    @property
    def lock_path(self):
        return self.path + ".lock"

    def _open(self, passphrase: str, legacy: bool = False):
        """Open the database, read the parameters and store the master fernet.
        :param passphrase: master passphrasse for the luggage (utf8 string)
        :param legacy: if True, the Luggage parameters are open using pickle instead of json (unsafe for tampered
          Luggages, but needed for Luggages created with cryptoluggage < 3.1.0).
        :return: (conn, fernet), where conn is the database connection and fernet
          is the master fernet to be used to decrypt the database.
        """
        conn = sqlite3.connect(self.path)
        c = conn.cursor()

        # Load public params
        for params_dumps, in c.execute(r"SELECT token FROM token_store"
                                       f" WHERE id={self.params_id:d}"):
            self.params = LuggageParams.loads(params_dumps, legacy=legacy)
            break
        else:
            raise ValueError(f"Could not find parameter entry id {self.params_id}")

        # Make master fernet
        master_fernet = LuggageFernet(key=LuggageFernet.key_from_password(
            password=passphrase, luggage_params=self.params))
        return conn, master_fernet

    @classmethod
    def _save_params(cls,
                     luggage_params: LuggageParams,
                     db_conn: sqlite3.Connection,
                     db_cursor: sqlite3.Cursor = None):
        """Save the Luggage parameters to the database. If db_cursor is not None, data are not commited.
        Otherwise, db_conn is used to obtain a cursor and the changes are committed."""
        commit = False
        if db_cursor is None:
            commit = True
            db_cursor = db_conn.cursor()

        db_cursor.execute(r"INSERT OR REPLACE INTO token_store (id, token) VALUES (?, ?)",
                          (cls.params_id, luggage_params.dumps()))
        if commit:
            db_conn.commit()

    def close(self):
        self.db_conn, self.master_fernet = None, None
        try:
            os.remove(self.lock_path)
        except FileNotFoundError as ex:
            pass
        try:
            self.lock.release(force=True)
        except AttributeError:
            # lock might not have been defined, that's okp
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __del__(self):
        self.close()

    def __len__(self):
        """
        :return: the number of tokens stored in the store
        """
        for x, in self.db_conn.cursor().execute("SELECT COUNT(*) from token_store"):
            return x
        else:
            raise BadPasswordOrCorruptedException()


class RestrictedUnpickler(pickle.Unpickler):
    """Only allow loading of specific safe classes. This should prevent code execution even if the 
    passphrase or key are compromised."""
    allowed_classes = {
        "SecretsDict": "cryptoluggage.luggage",
        "Dir": "cryptoluggage.model",
        "File": "cryptoluggage.model",
        "dict": "builtins",
        "list": "builtins",
        "str": "builtins",
        "int": "builtins",
        "float": "builtins",
        "set": "builtins",
        "tuple": "builtins",
        "SortedDict": "sortedcontainers.sorteddict",
    }

    def find_class(self, module, name):
        if name in self.allowed_classes and module == self.allowed_classes[name]:
            # Only allow explicitly whitelisted classes
            if module == 'cryptoluggage.luggage' and name == 'SecretsDict':
                return SecretsDict
            if module == 'cryptoluggage.model' and name == 'Dir':
                return model.Dir
            if module == 'cryptoluggage.model' and name == 'File':
                return model.File
            # Builtins
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"WARNING! Found '{module}.{name}' when unpickling. This could mean that "
            f"your passphrase was compromised and an attacker tampered with your Luggage.")


def restricted_loads(data):
    """Helper to load pickles with restricted classes."""
    return RestrictedUnpickler(io.BytesIO(data)).load()
