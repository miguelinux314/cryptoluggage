#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptoluggage for python 3

"""
__author__ = "Miguel Hernández Cabronero <miguel.hernandez@uab.cat>"
__date__ = "08/02/2020"

import os
import base64
import sqlite3
import pickle
import time
import struct
import filelock
import sortedcontainers
import string
# Cryptography specific imports
import cryptography.fernet
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from . import model


class RepeatedNameError(BaseException):
    """Raised when a repeated name is repeated, and that is not allowed.
    """
    pass


class LuggageInUseError(BaseException):
    """A luggage is being accessed, but it is already being
    open by another instance.
    """
    pass


class LuggageClosedError(BaseException):
    """A luggage was used after being closed
    """


class BadPasswordOrCorrupted(BaseException):
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
            raise BadPasswordOrCorrupted()

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)

        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise BadPasswordOrCorrupted()

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise BadPasswordOrCorrupted()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise BadPasswordOrCorrupted()
        return unpadded

    @classmethod
    def key_from_password(cls, password, luggage_params):
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
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
                b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()

        return basic_parts + hmac


class LuggageParams:
    """Parameters employed in a Luggage
    """

    def __init__(self, master_key_salt=None, master_key_iterations=1000000):
        """
        :param master_key_salt: salt used for deriving the master key. If none, os.urandom is called
        :param master_key_iterations: number of iterations used to derive the master key from a password
        """
        self.master_key_salt = os.urandom(16) if master_key_salt is None else master_key_salt
        assert master_key_iterations > 0
        self.master_key_iterations = int(master_key_iterations)


class SecretsDict(sortedcontainers.SortedDict):
    def __init__(self, luggage, *args, **kwargs):
        self.luggage = luggage
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.write_to_db(commit=True)

    def __delitem__(self, key):
        super().__delattr__(key)
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
            luggage._secrets.update(
                pickle.loads(luggage.master_fernet.decrypt_binary(secrets_token)))
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
                self.root = pickle.loads(self.luggage.master_fernet.decrypt_binary(root_node_token))
                break
            else:
                raise BadPasswordOrCorrupted(f"Could not find parameter entry id{self.secrets_id}.")
        else:
            self.root = root

    @property
    def children(self):
        self.root.children

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
        if any(c not in string.printable for c in virtual_path):
            raise ValueError("Virtual path contains non-printable characters")
        parents, file_name = os.path.split(virtual_path)
        parent_names = []
        while parents and os.path.normpath(parents) != "/":
            parents, parent_name = os.path.split(os.path.normpath(parents))
            parent_names.append(parent_name)
        return list(reversed(parent_names)), file_name

    def dir_from_parents(self, parent_names, create=True):
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
        return target_dir

    def print_hierarchy(self):
        """Print the filesystem hierarchy
        """
        print()
        self._print_node(node=self.root, level=0)

    def _print_node(self, node, level):
        s = " " * (3 * (level - 1)) + (" +-" if level > 0 else "")
        if node is not self.root or self.luggage.encrypted_fs.root is not self.root:
            print(s + f"[{node.name}]")
        else:
            print(f"[{self.luggage.path}]")
        try:
            for name, node in node.children.items():
                print(" " * (3 * (level)) + " |")
                self._print_node(node=node, level=level + 1)
        except AttributeError:
            pass

    def _replace_root_dumps(self, cursor):
        cursor.execute(r"REPLACE INTO token_store (id, token) VALUES (?, ?)",
                       (self.luggage.root_folder_id,
                        self.luggage.master_fernet.encrypt_binary(
                            self.luggage.encrypted_fs.dumps())))

    def __getitem__(self, virtual_path):
        """
        :param virtual_path: path to the element to be retrieved
        :return: if virtual_path points to a folder, an EncryptedFS instance
          is returned. If it points to a file, the contents (bytes) of the
          file are returned.
        """
        parent_names, file_name = self.split_path(virtual_path)
        target_dir = self.dir_from_parents(parent_names=parent_names, create=False)
        if not file_name:
            return EncryptedFS(luggage=self.luggage, root=target_dir)
        try:
            target = target_dir.children[file_name]
            if isinstance(target, model.Dir):
                return EncryptedFS(luggage=self.luggage, root=target)
            elif isinstance(target, model.File):
                cursor = self.luggage.db_conn.cursor()
                for token_data, in cursor.execute("SELECT token FROM token_store "
                                                  f"WHERE id={target.token_id:d}"):
                    return self.luggage.master_fernet.decrypt_binary(token_data)
        except KeyError as ex:
            raise KeyError(virtual_path) from ex

    def __setitem__(self, virtual_path, value):
        """Save a file to the virtual path, creating parent dirs as necessary.
        Path splitting is based on os.path. Paths may optionally include a leading os.sep.

        :param virtual_path: a str-like object that points to a file in the Luggage's
          virtual (encrypted) filesystem. Example paths are:
                /a.txt
                a.txt
          A file named a.txt at the luggage's root.
                /a/b/c.bin
                a/b/c.bin
          file named c.bin under b; b is a subdir of a;
          a is a subdir of the luggage's root.
        :param value: a str-like object with the input file's path, or an open file-like
            object that can be read()
        """
        # Process target path
        parent_names, file_name = self.split_path(virtual_path)
        if not file_name:
            raise KeyError(f"The virtual path {repr(virtual_path)} does not denote a file"
                           f" (it should)")
        target_dir = self.dir_from_parents(parent_names=parent_names)

        # Get file contents
        try:
            with open(value, "rb") as f:
                contents = f.read()
        except (TypeError, FileNotFoundError):
            try:
                contents = value.read()
            except AttributeError:
                raise ValueError(f"right value of type {type(value)} not valid")
        assert contents is not None

        # Store new token
        cursor = self.luggage.db_conn.cursor()
        cursor.execute(r"INSERT INTO token_store (token) VALUES (?)",
                       (self.luggage.master_fernet.encrypt_binary(data=contents),))
        new_file = model.File(name=file_name, parent=target_dir, token_id=cursor.lastrowid)
        target_dir.children[new_file.name] = new_file
        self._replace_root_dumps(cursor=cursor)
        self.luggage.db_conn.commit()

    def __delitem__(self, key):
        """Delete a file or a dir, recursively in the latter case
        """
        parent_names, name = self.split_path(key)
        target_dir = self.dir_from_parents(parent_names=parent_names, create=False)
        if not name:
            assert target_dir is not self.luggage.encrypted_fs.root
            target = target_dir
        else:
            target = target_dir.children[name]
        cursor = self.luggage.db_conn.cursor()
        try:
            # Assume it is a file
            cursor.execute(f"DELETE FROM token_store WHERE id={target.token_id:d}")
        except AttributeError:
            # It must be a directory
            for file in target.get_descendent_files():
                cursor.execute(f"DELETE FROM token_store WHERE id={file.token_id:d}")

        del target.parent.children[target.name]
        self._replace_root_dumps(cursor)
        self.luggage.db_conn.commit()

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

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.root)})"


class Luggage:
    """Luggage (encrypted database for secrets and files).
    """
    root_folder_id, secrets_id, params_id = range(-3, 0)

    def __init__(self, path: str, passphrase: str):
        """Open a luggage for the given password, generating a new one if
        it does not exist.
        """
        self.path = path
        if not os.path.exists(self.path):
            self.create_new(path=self.path,
                            passphrase=passphrase)
        self.db_conn, self.master_fernet = self._open(password=passphrase)
        existed_before = os.path.exists(self.lock_path)
        self.lock = filelock.FileLock(lock_file=self.lock_path)
        try:
            self.lock.acquire(timeout=0.1)
        except filelock.Timeout as ex:
            if not existed_before:
                try:
                    os.remove(self.lock_path)
                except Exception as ex:
                    pass

            raise LuggageInUseError(
                f"The Luggage {self.path} seems to be already opened elsewhere.\n"
                f"If you are sure this is not the case, remove {self.lock_path} "
                "and try again") from ex

    @classmethod
    def create_new(cls, path, passphrase: str):
        """Create a new Luggage (encrypted DB) at target_path for the given
        master password.

        :return: a Luggage instance
        """
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
        c.execute(r"INSERT INTO token_store (id, token) VALUES (?, ?)",
                  (cls.params_id, pickle.dumps(luggage_params)))

        # root and secrets are encrypted
        master_fernet = LuggageFernet(key=LuggageFernet.key_from_password(
            password=passphrase, luggage_params=luggage_params))
        secrets = {}
        empty_root = model.Dir(name="__root__")
        for db_id, instance in ((cls.root_folder_id, empty_root),
                                (cls.secrets_id, secrets)):
            c.execute(r"INSERT INTO token_store (id, token) VALUES (?, ?)",
                      (db_id, master_fernet.encrypt_binary(pickle.dumps(instance))))

        conn.commit()
        return Luggage(path=path, passphrase=passphrase)

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

    def _open(self, password):
        """Open the database, read the parameters and store the master fernet.
        :return: (conn, fernet), where conn is the database connection and fernet
        is the master fernet to be used to decrypt the database.
        """
        conn = sqlite3.connect(self.path)
        c = conn.cursor()

        # Load public params
        for params_dumps, in c.execute(r"SELECT token FROM token_store"
                                       f" WHERE id={self.params_id:d}"):
            self.params = pickle.loads(params_dumps)
            break
        else:
            raise ValueError(f"Could not find parameter entry id {self.params_id}")

        # Make master fernet
        master_fernet = LuggageFernet(key=LuggageFernet.key_from_password(
            password=password, luggage_params=self.params))
        return conn, master_fernet

    def close(self):
        self.db_conn, self.master_fernet = None, None
        try:
            os.remove(self.lock_path)
        except FileNotFoundError:
            pass
        self.lock.release(force=True)

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
            raise BadPasswordOrCorrupted()
