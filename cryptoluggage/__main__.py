#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cryptoluggage's entry point
"""

import argparse
import collections
import csv
import getpass
import inspect
import os
import prompt_toolkit
import prompt_toolkit.auto_suggest
from prompt_toolkit import print_formatted_text
import qrcode
import re
import shlex
import shutil
import sys
import textwrap

import cryptoluggage
from cryptoluggage.luggage import BadPathException, OverwriteRefuseError


class CommandNotFoundError(Exception):
    pass


class SecretNotFoundError(Exception):
    def __init__(self, secret_name):
        super().__init__(f"Secret '{secret_name}' not found.")
        self.secret_name = secret_name


class InvalidParametersError(Exception):
    pass


class AutoFire:
    """Automatic CLI helper based on Google's fire.
    """
    name_to_fun = collections.OrderedDict({})

    @classmethod
    def exported_function(cls, aliases=[]):
        def import_function_wrapper(fun):
            names = list(aliases)
            if not names:
                names.append(fun.__name__)
            for name in aliases:
                if name in cls.name_to_fun:
                    raise SyntaxError(f"{name} already defined (set to {cls.name_to_fun[name].__name__}")
                cls.name_to_fun[name] = fun
            return fun

        return import_function_wrapper

    def print_help(self, fun_name=None, show_version=True):
        """Print help.
        """
        if show_version:
            print_formatted_text(prompt_toolkit.formatted_text.FormattedText([
                ("", "You are using "),
                ("bold", f"CryptoLuggage v{cryptoluggage.__version__}"),
                ("", "."),
                ("", " These are the available commands:\n" if fun_name is None else "\n"),
            ]))

        fun_to_names = collections.defaultdict(list)
        for name, fun in self.name_to_fun.items():
            fun_to_names[fun].append(name)
        for name, fun in self.name_to_fun.items():
            names = fun_to_names[fun]
            if name != names[0]:
                continue
            if fun_name is not None and not any(fun_name == n for n in names):
                continue
            shown_args = list(inspect.getfullargspec(fun)[0])
            defaults = inspect.getfullargspec(fun)[3]

            if shown_args[0] == "self":
                shown_args = shown_args[1:]
            for i, arg in enumerate(shown_args):
                try:
                    shown_args[i] = f"{shown_args[i]}"
                    if defaults and i >= len(shown_args) - len(defaults):
                        shown_args[i] += f"={defaults[i - (len(shown_args) - len(defaults))]!r}"
                except IndexError:
                    pass

            doc = inspect.getdoc(fun) or ""
            if doc:
                shown_doc = " ".join(line.strip() for line in doc.splitlines() if line.strip())
            else:
                shown_doc = ""

            format_text_tuples = []
            for name in names:
                format_text_tuples.append(("bold", f"{name} "))
                format_text_tuples.append(("bold", " ".join(f"<{arg}>" for arg in shown_args)))
                format_text_tuples.append(("", "\n"))
            format_text_tuples = format_text_tuples[:-1]  # Remove last \n
            print_formatted_text(prompt_toolkit.formatted_text.FormattedText(format_text_tuples))
            if shown_doc:
                print(textwrap.fill(shown_doc, width=shutil.get_terminal_size().columns))
            print()
            if fun_name is not None:
                break
        else:
            if fun_name is not None:
                raise KeyError(fun_name)

    name_to_fun["help"] = print_help

    def fire(self, command, *args):
        try:
            fun = self.name_to_fun[command]
            fun(self, *args)
        except KeyError:
            raise CommandNotFoundError(command)
        except TypeError:
            raise InvalidParametersError(command)


class Main(AutoFire):
    def __init__(self, luggage):
        self.luggage = luggage

    @AutoFire.exported_function(["scat", "sprint"])
    def print_secret(self, secret_key):
        """Show the contents of a secret.
        """
        secret_name = self.parse_secret_name_or_index(param=secret_key)
        if secret_key != secret_name:
            print(f"Showing secret '{secret_name}':")
        print(self.luggage.secrets[secret_name])

    @AutoFire.exported_function(["qr"])
    def print_secret_qr(self, secret_key, prefix="pass:"):
        """Show the contents of a secret and display a QR for all '<prefix> <pass>' lines.
        By default, prefix is 'pass:'. Spaces between the prefix and the pass, and all spaces after the pass
        are automatically ignored."""
        colon_warn_text = prompt_toolkit.formatted_text.FormattedText([
            ("bold", "Warning: "),
            ("", f"prefix usually contains a colon (:), but yours doesn't ({prefix!r}) "
                 f"and the qr contains a possibly spurious colon as prefix."),
        ])

        secret_name = self.parse_secret_name_or_index(param=secret_key)
        if secret_key != secret_name:
            print(f"Showing secret '{secret_name}':")
        rexp = r"\s*" + str(prefix.replace(" ", r"\s*")) + r"\s*(.+)\s*"
        for line in self.luggage.secrets[secret_name].splitlines():
            print(line)
            match = re.match(rexp, line, re.IGNORECASE)
            if match:
                qr = qrcode.QRCode(version=7)
                qr.add_data(match.group(1))
                qr.make()

                if ":" not in prefix and match.group(1).strip().startswith(":"):
                    print_formatted_text(colon_warn_text)
                qr.print_ascii(invert=True)
                if ":" not in prefix and match.group(1).strip().startswith(":"):
                    print_formatted_text(colon_warn_text)

    @AutoFire.exported_function(["sset"])
    def write_secret(self, secret_key):
        """Edit secret with name secret_key. If the name doesn't exist, a new one can be created.
        """
        try:
            secret_name = self.parse_secret_name_or_index(param=secret_key)
        except KeyError:
            secret_name = secret_key
        try:
            self.luggage.secrets[secret_name] = prompt_toolkit.prompt(
                f"Editing secret '{secret_name}'. ESC,Enter to save. Ctrl+C to cancel.\n\n",
                multiline=True,
                default=self.luggage.secrets[secret_name] if secret_name in self.luggage.secrets else "")
        except KeyboardInterrupt:
            print(f"Aborting editing of secret '{secret_name}'")
            pass

    @AutoFire.exported_function(["sls", "slist"])
    def list_secrets(self, filter=None):
        """List all secrets. If filter is provided, only secrets that contain that string in the name are shown."""
        if not self.luggage.secrets:
            print("No secrets stored.")
            return
        if not filter:
            for i, secret_name in enumerate(self.luggage.secrets):
                print(f"[{i}] {secret_name}")
        else:
            filter = filter.lower()
            matches_found = False
            for i, secret_name in enumerate(self.luggage.secrets):
                if filter in secret_name.lower():
                    print(f"[{i}] {secret_name}")
                    matches_found = True
            if not matches_found:
                print(f"No secrets found matching filter {filter!r}.")

    @AutoFire.exported_function(["isecrets", "is"])
    def import_secret_csv(self, csv_path):
        """Import a CSV of secrets into the luggage.
        The CSV must have at least two columns. The first column must contain keys
        and the second column must contain their values.
        """
        with open(os.path.expanduser(csv_path), "r") as secrets_file:
            rows = [r[:2] for r in list(csv.reader(secrets_file))]

        secret_dict = {name: value for name, value in rows}
        existing_secret_count = sum(1 for n in secret_dict.keys() if n in self.luggage.secrets)
        if existing_secret_count:
            if str(existing_secret_count) != prompt_toolkit.prompt(
                    f"About to overwrite {existing_secret_count} elements. Type {existing_secret_count} to confirm: "):
                print("Typed text did not match. (Nothing was inserted nor overwriten)")
                return
        for name, value in rows:
            self.luggage.secrets[name] = value
            
    @AutoFire.exported_function(["esecrets", "es"])
    def export_secret_csv(self, csv_path):
        """Export all secrets into a unencrypted CSV file.
        The CSV will have two columns. The first column will contain keys and the second column 
        will contain their values.
        """
        with open(os.path.expanduser(csv_path), "w") as secrets_file:
            for name, value in sorted(self.luggage.secrets.items()):
                secrets_file.write(f'"{name}","{value}"\n')

    @AutoFire.exported_function(["srm", "rmsecret"])
    def delete_secret(self, secret_name):
        """Delete a secret from the luggage given its name or its index."""
        del self.luggage.secrets[self.parse_secret_name_or_index(secret_name)]

    @AutoFire.exported_function(["tree"])
    def print_tree(self, filter=None):
        """Print a tree representation of the stored files. If filter is not None, only nodes containing that string in their paths are shown.
        """
        self.luggage.encrypted_fs.print_tree(filter_string=filter)

    @AutoFire.exported_function(["ls", "fls"])
    def print_file_list(self, filter=None):
        """Print a list representation of the stored files.
        If filter is not None, only nodes containing that string in their paths
        are shown.
        """
        self.luggage.encrypted_fs.print_node_list(filter_string=filter)

    @AutoFire.exported_function(["ecp"])
    def extract_file_or_dir(self, virtual_path, output_path):
        """Extract luggage's file at virtual_path into output_path in the disk.
        This method does not delete_node the file in the luggage.
        """
        try:
            self.luggage.encrypted_fs.export(
                virtual_path=virtual_path, output_path=output_path)
        except BadPathException:
            print(f"Path {virtual_path!r} not found in the luggage (maybe a typo, or missing the parent folders?). "
                  f"Nothing was extracted.")

    @AutoFire.exported_function(["icp"])
    def insert_file_or_dir(self, disk_path, virtual_path):
        """Insert a disk's file or directory into the luggage's filesystem at virtual_path.
        """
        disk_path = os.path.expanduser(disk_path)
        try:
            self.luggage.encrypted_fs[virtual_path] = os.path.expanduser(disk_path)
        except OverwriteRefuseError as ex:
            print(f"Path {ex.path!r} already exists in the luggage, refusing to overwrite. "
                  f"You can use `rm {ex.path}` to delete the existing file.")
        except BadPathException as ex:
            print(f"Error inserting {disk_path!r} into the luggage: {ex}.")

    @AutoFire.exported_function(["mv", "fmv"])
    def move(self, source_path, target_path):
        """Move source_path into target_path in the luggage's filesystem.
        """
        try:
            self.luggage.encrypted_fs.move(source_path=source_path, target_path=target_path)
        except KeyError as ex:
            print(f"Error moving file: {ex} not found in the luggage.")
        except BadPathException as ex:
            print(f"Error moving file: {ex}.")
        except OverwriteRefuseError as ex:
            print(f"Error moving file: destination already exists and overwriting is refused. "
                  f"You can delete the destination first with `rm {ex.path}`.")

    @AutoFire.exported_function(["frm", "rm"])
    def delete_node(self, virtual_path):
        """Delete virtual_path from the luggage's filesystem.
        If virtual_path is a directory, all descendents are deleted recursively.
        """
        try:
            target_node = self.luggage.encrypted_fs.get_node(virtual_path)
        except KeyError:
            raise cryptoluggage.BadPathException(f"Path {virtual_path} not found.")
        if not target_node.parent:
            raise cryptoluggage.BadPathException(f"Deleting root folder is not supported")

        deleting_nodes = sum(1 for _ in target_node.get_descendents(get_files=True, get_dirs=True))
        if str(deleting_nodes) == prompt_toolkit.prompt(
                f"About to delete {deleting_nodes} element{'s' if deleting_nodes > 1 else ''}. "
                f"Type {deleting_nodes} to confirm: "):
            del self.luggage.encrypted_fs[virtual_path]
            print(f"Deleted {target_node.path}.")
        else:
            print("Typed text did not match. (Nothing was deleted)")

    @AutoFire.exported_function(["passwd"])
    def change_password(self):
        """Change the luggage's passphrase."""
        print("You are about to change the luggage's passphrase. "
              "It is recommended you back up your original luggage first "
              "(this tool will not do it for you).")
        new_passphrase = getpass.getpass(prompt="New passphrase: ")
        confirm_passphrase = getpass.getpass(prompt="Repeat new passphrase: ")
        if new_passphrase != confirm_passphrase:
            print("Passwords do not match. Try again.")
            return
        
        self.luggage.change_passphrase(new_passphrase)
        
        print("Passphrase changed successfully.")

    @AutoFire.exported_function(["quit", "exit"])
    def exit_luggage(self):
        """Close the current Luggage and exit."""
        print("Bye")
        sys.exit(0)

    def parse_secret_name_or_index(self, param):
        """Return a secret's name contained in the luggage.
        If it denotes an existing file name, that name is returned.
        If it doesn't and it is an integer, the name of the secret at that
        position is returned. Otherwise, a SecretNotFoundError exception is raised.
        """
        if not param in self.luggage.secrets:
            try:
                param = tuple(self.luggage.secrets.keys())[int(param)]
            except (ValueError, KeyError, IndexError):
                raise SecretNotFoundError(param)
        return param


def __main__():
    invocation_parser = argparse.ArgumentParser()
    invocation_subparsers = invocation_parser.add_subparsers(dest="command")
    open_parser = invocation_subparsers.add_parser("open")
    open_parser.add_argument("luggage_path")
    open_parser.add_argument(
        "--legacy", action="store_true", default=False,
        help="Open a Luggage created with version < 3.1.0. "
             "UNSAFE! unless you are sure the Luggage has not been tampered with. "
             "After opening in legacy mode, the Luggage will be upgraded to the new format.")
    create_parser = invocation_subparsers.add_parser("create")
    create_parser.add_argument("luggage_path")

    options = invocation_parser.parse_args()
    if options.command is None:
        invocation_parser.print_help()
        print()
        print("Error: Insufficient commands\n")
        sys.exit(-1)
    elif options.command == "open":
        try:
            passphrase = getpass.getpass("Passphrase: ")
        except KeyboardInterrupt:
            print()
            sys.exit(-1)
        try:
            luggage = cryptoluggage.Luggage(
                path=os.path.expanduser(options.luggage_path),
                passphrase=passphrase,
                legacy=options.legacy)
        except cryptoluggage.BadPasswordOrCorruptedException:
            print(f"Cannot open {options.luggage_path}. Is the password OK?")
            sys.exit(-1)
    elif options.command == "create":
        passphrase = getpass.getpass("Passphrase: ")
        confirmed_passphrase = getpass.getpass("Confirm passphrase: ")
        if passphrase == confirmed_passphrase:
            luggage = cryptoluggage.Luggage.create_new(
                path=os.path.expanduser(options.luggage_path),
                passphrase=passphrase)
        else:
            print("Passwords do not match. Try again.")
            sys.exit(-1)
    else:
        raise RuntimeError(f"Unrecognized command {options.command}")
    del options

    index = 0
    speed = 1
    session = prompt_toolkit.PromptSession()
    main = Main(luggage=luggage)
    while True:
        try:
            prompt = "Luggage"
            formatted_text = prompt_toolkit.formatted_text.FormattedText([
                ("#ffe37d bold", "◐ "),
                ("#aaaaaa bold", prompt[:index]),
                ("#ff5500 bold", prompt[index]),
                ("#aaaaaa bold", prompt[index + 1:]),
                ("#ffe37d bold", " ◑ "),
            ])
            index += speed
            speed = -speed if not 0 < index < len(prompt) - 1 else speed

            commands = shlex.split(
                session.prompt(formatted_text, auto_suggest=prompt_toolkit.auto_suggest.AutoSuggestFromHistory()))
            if not commands:
                continue
            try:
                main.fire(commands[0], *commands[1:])
            except CommandNotFoundError:
                print(f"Unrecognized command {commands[0]!r}. Type 'help' to see available commands.")
            except SecretNotFoundError as ex:
                print(f"Secret {ex.secret_name!r} not found.")
            except InvalidParametersError:
                print(f"Invalid parameters for command {commands[0]!r}.\nType 'help {commands[0]}' to see usage.")
        except (KeyboardInterrupt, EOFError):
            main.exit_luggage()


if __name__ == '__main__':
    __main__()
