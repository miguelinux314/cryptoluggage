#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cryptoluggage for python 3

"""
__author__ = "Miguel Hernández Cabronero <miguel.hernandez@uab.cat>"
__date__ = "08/02/2020"

import sys
import os
import argparse
import base64
import sqlite3
import pickle
import cryptography
import cryptography.fernet
import time
import struct
import filelock
#
import six
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.fernet import InvalidToken
#
import sortedcontainers

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

        # No Base64 decryption
        # try:
        #     data = base64.urlsafe_b64decode(token)
        # except (TypeError, binascii.Error):
        #     raise InvalidToken
        data = token
        if not data or six.indexbytes(data, 0) != 0x80:
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

    @classmethod
    def empty_fernet(cls):
        params = LuggageParams(master_key_salt=bytes(0), master_key_iterations=1)
        empty_key = cls.key_from_password(password="", luggage_params=params)
        return cls(empty_key)

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
        cursor = luggage.db_conn.cursor()
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


class EncryptedDir(model.Dir):
    def __init__(self, luggage):
        self.luggage = luggage
        super().__init__(name="__root__")

    def dumps(self):
        return pickle.dumps(model.Dir(name=self.name, children=self.children))

    def insert_file(self, src_path, destination_path, create_parents=False):
        """
        :param src_path: real path to the file to be inserted
        :param destination_path: virtual path of the file in the luggage.
          Paths are of the form "[/][dir1/ [dir2/ [...]] file_name.
          Files are overwritten if virtual paths existed.
        :param create_parents: if False, all specified parent dirs must exist
          in the luggage. Otherwise, they are created if they don't.
        :return: a model.File instance describing the inserted file
        """
        assert os.path.isfile(src_path)

        target_dir, file_name = os.path.split(destination_path)

        if destination_path.startswith("/"):
            destination_path = destination_path[1:]


class EncryptedRoot:
    pass


# TODO: HERE HERE HERE HERE


class Luggage:
    """Luggage (encrypted database for secrets and files).
    """
    root_folder_id, secrets_id, params_id = range(-3, 0)

    def __init__(self, luggage_path: str, password: str):
        """Open a luggage for the given password, generating a new one if
        it does not exist.
        """
        self.luggage_path = luggage_path
        if not os.path.exists(self.luggage_path):
            self.create_new(target_path=self.luggage_path,
                            master_password=password)
        self.db_conn, self.master_fernet = self._open(password=password)
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
                f"The Luggage {self.luggage_path} seems to be already opened elsewhere.\n"
                f"If you are sure this is not the case, remove {self.lock_path} "
                "and try again") from ex

    def close(self):
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

    @property
    def secrets(self):
        try:
            return self._secrets
        except AttributeError:
            return SecretsDict.read_from_db(self)

    @property
    def fs_root(self):
        """Get the encrypted file system's root node
        (reading it if not currently present)
        """
        try:
            return self._fs_root
        except AttributeError:
            cursor = self.db_conn.cursor()
            # Load encrypted fs root
            for root_node_token, in cursor.execute(r"SELECT token FROM token_store"
                                                   f" WHERE id={self.root_folder_id:d}"):
                self._fs_root = pickle.loads(self.master_fernet.decrypt_binary(root_node_token))
                return self._fs_root
            else:
                raise ValueError(f"Could not find parameter entry id{self.secrets_id}")

    @classmethod
    def create_new(cls, target_path, master_password: str):
        """Create a new Luggage (encrypted DB) at target_path for the given
        master password.

        :return: a Luggage instance
        """
        try:
            os.remove(target_path)
        except FileNotFoundError:
            pass

        conn = sqlite3.connect(target_path)
        c = conn.cursor()
        c.execute(r"CREATE TABLE token_store ("
                  r"    id INTEGER PRIMARY KEY, "
                  r"    token BLOB)")
        c.execute(r"CREATE UNIQUE INDEX index_token_store ON token_store (id)")

        # Parameters are public - no password
        empty_fernet = LuggageFernet.empty_fernet()
        luggage_params = LuggageParams()
        params_token = empty_fernet.encrypt_binary(pickle.dumps(luggage_params))
        c.execute(r"INSERT INTO token_store (id, token) VALUES (?, ?)",
                  (cls.params_id, params_token))

        # root and secrets are encrypted
        master_fernet = LuggageFernet(key=LuggageFernet.key_from_password(
            password=master_password, luggage_params=luggage_params))
        secrets = {}
        empty_root = model.Dir(name="luggage://")
        for db_id, instance in ((cls.root_folder_id, empty_root),
                                (cls.secrets_id, secrets)):
            c.execute(r"INSERT INTO token_store (id, token) VALUES (?, ?)",
                      (db_id, master_fernet.encrypt_binary(pickle.dumps(instance))))

        conn.commit()
        return Luggage(luggage_path=target_path, password=master_password)

    @property
    def lock_path(self):
        return self.luggage_path + ".lock"

    def _open(self, password):
        """Open the database, read the parameters and store the master fernet.
        :return: (conn, fernet), where conn is the database connection and fernet
        is the master fernet to be used to decrypt the database.
        """
        assert os.path.isfile(self.luggage_path)
        conn = sqlite3.connect(self.luggage_path)
        c = conn.cursor()

        # Load public params
        empty_fernet = LuggageFernet.empty_fernet()
        for params_id_token, in c.execute(r"SELECT token FROM token_store"
                                          f" WHERE id={self.params_id:d}"):
            self.params = pickle.loads(empty_fernet.decrypt_binary(params_id_token))
            break
        else:
            raise ValueError(f"Could not find parameter entry id {self.params_id}")

        # Make master fernet
        master_fernet = LuggageFernet(key=LuggageFernet.key_from_password(
            password=password, luggage_params=self.params))
        return conn, master_fernet


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CryptoLuggage CLI")
    parser.add_argument("-v", "--verbose", help="Be verbose? Repeat for more", action="count", default=0)
    parser.add_argument("luggage", help="Path to the luggage to be used")
    options = parser.parse_known_args()[0]
