#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cryptoluggage's entry point
"""

import os
import sys
import argparse
import getpass
import shlex
import prompt_toolkit
import prompt_toolkit.auto_suggest
import csv
import collections
import inspect

import cryptoluggage


class CommandNotFoundError(Exception):
    pass

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

    def print_help(self, fun_name=None):
        """Print help.
        """
        print("Usage:")
        fun_to_names = collections.defaultdict(list)
        for name, fun in self.name_to_fun.items():
            fun_to_names[fun].append(name)
        for name, fun in self.name_to_fun.items():
            names = fun_to_names[fun]
            if name != names[0]:
                continue
            if fun_name is not None and not any(fun_name == n for n in names):
                continue
            shown_args = inspect.getfullargspec(fun)[0]
            defaults = inspect.getfullargspec(fun)[3]
            if shown_args[0] == "self":
                shown_args = shown_args[1:]
            for i, arg in enumerate(shown_args):
                try:
                    shown_args[i] = f"{shown_args[i]}{'=' + str(defaults[i]) if defaults else ''}"
                except IndexError:
                    pass

            shown_doc = [line.strip() for line in (fun.__doc__.splitlines() if fun.__doc__ else "")]
            shown_doc = [l for l in shown_doc if l]

            if fun_name is None and shown_doc:
                shown_doc[0] += (" ..." if len(shown_doc) > 1 else '')
                shown_doc = shown_doc[:1]

            shown_doc = "\n".join(shown_doc)
            print(('\t' if fun_name is None else '') + f"{', '.join(names)}({', '.join(shown_args)}):\n{shown_doc}")
            print()
            if fun_name is not None:
                break
        else:
            if fun_name is not None:
                raise KeyError(fun_name)
        print()

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

    @AutoFire.exported_function(["sset"])
    def write_secret(self, secret_key):
        """Edit secret with name secret_key.
        If the name doesn't exist, a new one can be created.
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
        """List all secrets.
        If filter is provided, only secrets that contain that string in the name are shown."""
        if not self.luggage.secrets:
            print("No secrets stored.")
            return
        if not filter:
            for i, secret_name in enumerate(self.luggage.secrets):
                print(f"[{i}] {secret_name}")
        else:
            filter = filter.lower()
            for i, secret_name in enumerate(self.luggage.secrets):
                if filter in secret_name.lower():
                    print(f"[{i}] {secret_name}")

    @AutoFire.exported_function(["tree"])
    def print_tree(self, filter=None):
        """Print a tree representation of the stored files.
        If filter is not None, only nodes containing that string in their paths
        are shown.
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
        self.luggage.encrypted_fs.export(
            virtual_path=virtual_path, output_path=output_path)

    @AutoFire.exported_function(["icp"])
    def insert_file_or_dir(self, disk_path, virtual_path):
        """Insert a disk's file or directory into the luggage's filesystem at virtual_path.
        """
        disk_path = os.path.expanduser(disk_path)
        self.luggage.encrypted_fs[virtual_path] = os.path.expanduser(disk_path)

    @AutoFire.exported_function(["mv", "fmv"])
    def move(self, source_path, target_path):
        """Move source_path into target_path in the luggage's filesystem.
        """
        self.luggage.encrypted_fs.move(source_path=source_path, target_path=target_path)

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
                f"About to delete_node {deleting_nodes} elements. Type {deleting_nodes} to confirm: "):
            del self.luggage.encrypted_fs[virtual_path]
            print(f"Deleted {target_node.path}.")
        else:
            print("Typed text did not match. (Nothing was deleted)")

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

    @AutoFire.exported_function(["srm", "rmsecret"])
    def delete_secret(self, secret_name):
        del self.luggage.secrets[self.parse_secret_name_or_index(secret_name)]

    @AutoFire.exported_function(["quit", "exit"])
    def exit_luggage(self):
        """Exit.
        """
        print("Bye")
        sys.exit(0)

    def parse_secret_name_or_index(self, param):
        """Return a secret's name contained in the luggage.
        If it denotes an existing file name, that name is returned.
        If it doesn't and it is an integer, the name of the secret at that
        position is returned. Otherwise, a KeyError exception is rised.
        """
        if not param in self.luggage.secrets:
            try:
                param = tuple(self.luggage.secrets.keys())[int(param)]
            except (ValueError, KeyError, IndexError):
                raise KeyError(param)
        return param


def __main__():
    invocation_parser = argparse.ArgumentParser()
    invocation_subparsers = invocation_parser.add_subparsers(dest="command")
    open_parser = invocation_subparsers.add_parser("open")
    open_parser.add_argument("luggage_path")
    create_parser = invocation_subparsers.add_parser("create")
    create_parser.add_argument("luggage_path")

    options = invocation_parser.parse_args()
    if options.command is None:
        invocation_parser.print_help()
        print()
        print("Error: Insufficient commands\n")
        sys.exit(-1)
    elif options.command == "open":
        passphrase = getpass.getpass("Passphrase: ")
        try:
            luggage = cryptoluggage.Luggage(path=os.path.expanduser(options.luggage_path), passphrase=passphrase)
        except cryptoluggage.BadPasswordOrCorruptedException:
            print(f"Cannot open {options.luggage_path}. Is the password OK?")
            sys.exit(-1)
    elif options.command == "create":
        passphrase = getpass.getpass("Passphrase: ")
        confirmed_passphrase = getpass.getpass("Confirm passphrase: ")
        if passphrase == confirmed_passphrase:
            luggage = cryptoluggage.Luggage.create_new(path=os.path.expanduser(options.luggage_path),
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
                r = main.fire(commands[0], *commands[1:])
            except CommandNotFoundError:
                main.print_help()
                print(f"Command {commands[0]} not found.")
            except InvalidParametersError:
                print(f"Invalid parameters for {commands[0]}.")
            # except KeyError as ex:
            #     main.print_help()
            #     print(f"Key {ex} not found.\nUsage:")
            # except TypeError as ex:
            #     main.print_help()
            #     print(f"{type(ex)}: {ex}")
            #     raise ex
        except (KeyboardInterrupt, EOFError):
            main.exit_luggage()


if __name__ == '__main__':
    __main__()
