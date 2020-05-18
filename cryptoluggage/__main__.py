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

import cryptoluggage

def parse_secret_name_or_index(luggage, param):
    """Return a secret's name contained in the luggage.
    If it denotes an existing file name, that name is returned.
    If it doesn't and it is an integer, the name of the secret at that
    position is returned. Otherwise, a KeyError exception is rised.
    """
    if not param in luggage.secrets:
        try:
            param = tuple(luggage.secrets.keys())[int(param)]
        except (ValueError, KeyError):
            raise KeyError(param)
    return param

def print_secret(options):
    secret_name = parse_secret_name_or_index(luggage=options.luggage, param=options.secret_key)
    if options.secret_key != secret_name:
        print(f"Showing secret key {secret_name}:\n")
    print(options.luggage.secrets[secret_name])

def write_secret(options):
    secret_name = parse_secret_name_or_index(luggage=options.luggage, param=options.secret_key)
    try:
        options.luggage.secrets[secret_name] = prompt_toolkit.prompt(
            f"Editing secret '{secret_name}'. ESC,Enter to save. Ctrl+C to cancel.\n\n",
            multiline=True,
            default=options.luggage.secrets[secret_name] if secret_name in options.luggage.secrets else "")
    except KeyboardInterrupt:
        print(f"Aborting editing of secret '{secret_name}'")
        pass


def list_secrets(options):
    if not options.filter:
        for i, secret_name in enumerate(options.luggage.secrets):
            print(f"[{i}] {secret_name}")
    else:
        filter = options.filter.lower()
        for i, secret_name in enumerate(options.luggage.secrets):
            if filter in secret_name.lower():
                print(f"[{i}] {secret_name}")


def print_tree(options):
    options.luggage.encrypted_fs.print_tree(filter_string=options.filter)


def list_files(options):
    options.luggage.encrypted_fs.print_node_list(filter_string=options.filter)


def extract_file_or_dir(options):
    options.luggage.encrypted_fs.export(
        virtual_path=options.virtual_path, output_path=options.output_path)


def insert_file_or_dir(options):
    file_or_dir_path = os.path.expanduser(options.file_or_dir_path)
    options.luggage.encrypted_fs[options.luggage_path] = os.path.expanduser(file_or_dir_path)


def move(options):
    options.luggage.encrypted_fs.move(source_path=options.source_virtual_path, target_path=options.target_virtual_path)

def delete(options):
    try:
        target_node = options.luggage.encrypted_fs.get_node(options.virtual_path)
    except KeyError:
        raise cryptoluggage.BadPathException(f"Path {options.virtual_path} not found.")
    if not target_node.parent:
        raise cryptoluggage.BadPathException(f"Deleting root folder is not supported")

    deleting_nodes = sum(1 for _ in target_node.get_descendents(get_files=True, get_dirs=True))
    if str(deleting_nodes) == prompt_toolkit.prompt(
            f"About to delete {deleting_nodes} elements. Type {deleting_nodes} to confirm: "):
        del options.luggage.encrypted_fs[options.virtual_path]
        print(f"Deleted {target_node.path}.")
    else:
        print("Typed text did not match. (Nothing was deleted)")

def import_secret_csv(options):
    with open(os.path.expanduser(options.csv_path), "r") as secrets_file:
        rows = [r[:2] for r in list(csv.reader(secrets_file))]
        
    
    secret_dict = {name: value for name, value in rows}
    existing_secret_count = sum(1 for n in secret_dict.keys() if n in options.luggage.secrets)
    if existing_secret_count:
        if str(existing_secret_count) != prompt_toolkit.prompt(
                f"About to overwrite {existing_secret_count} elements. Type {existing_secret_count} to confirm: "):
            print("Typed text did not match. (Nothing was inserted nor overwriten)")
            return

    for name, value in rows:
        options.luggage.secrets[name] = value



def exit_luggage(options=None):
    print("Bye")
    sys.exit(0)


if __name__ == '__main__':
    invocation_parser = argparse.ArgumentParser()
    invocation_subparsers = invocation_parser.add_subparsers(dest="command")
    open_parser = invocation_subparsers.add_parser("open")
    open_parser.add_argument("luggage_path")
    create_parser = invocation_subparsers.add_parser("create")
    create_parser.add_argument("luggage_path")

    options = invocation_parser.parse_args()
    if options.command is None:
        print("Error: Insufficient commands\n")
        invocation_parser.print_help()
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

    try:
        command_parser = argparse.ArgumentParser()
        command_subparsers = command_parser.add_subparsers(dest="command")

        parser_read_secret = command_subparsers.add_parser(
            "rsecret", aliases=["scat"], help="Read a secret from the luggage")
        parser_read_secret.add_argument("secret_key")
        parser_read_secret.set_defaults(func=print_secret, luggage=luggage)

        parser_write_secret = command_subparsers.add_parser(
            "wsecret", aliases=["sset"], help="Write a secret into the luggage")
        parser_write_secret.add_argument("secret_key", help="Key (name) of the secret")
        parser_write_secret.set_defaults(func=write_secret, luggage=luggage)

        parser_list_secrets = command_subparsers.add_parser(
            "lsecrets", aliases=["sls"], help="List existing secrets")
        parser_list_secrets.add_argument("filter", help="Show only secrets containing this string", nargs="?")
        parser_list_secrets.set_defaults(func=list_secrets, luggage=luggage)

        parser_import_secrets = command_subparsers.add_parser(
            "isecrets", aliases=["is"], help="Import a CSV of secrets (2 columns: name and contents.")
        parser_import_secrets.add_argument("csv_path")
        parser_import_secrets.set_defaults(func=import_secret_csv, luggage=luggage)

        parser_list_files = command_subparsers.add_parser(
            "lfiles", aliases=["ls", "fls"], help="List existing files")
        parser_list_files.add_argument("filter", help="Show only files containing this string in their virtual path",
                                       nargs="?")
        parser_list_files.set_defaults(func=list_files, luggage=luggage)

        parser_tree_files = command_subparsers.add_parser(
            "tree", help="Show a tree of existing files")
        parser_tree_files.add_argument("filter", help="Show only files containing this string in their virtual path",
                                       nargs="?")
        parser_tree_files.set_defaults(func=print_tree, luggage=luggage)

        parser_extract_file = command_subparsers.add_parser(
            "efile", aliases=["ecp"], help="Extract a file or a directory from the luggage to disk")
        parser_extract_file.add_argument("virtual_path")
        parser_extract_file.add_argument("output_path")
        parser_extract_file.set_defaults(func=extract_file_or_dir, luggage=luggage)

        parser_insert_file = command_subparsers.add_parser(
            "ifile", aliases=["icp"], help="Insert a file or a directory from disk to the luggage")
        parser_insert_file.add_argument("file_or_dir_path")
        parser_insert_file.add_argument("luggage_path")
        parser_insert_file.set_defaults(func=insert_file_or_dir, luggage=luggage)

        parser_move = command_subparsers.add_parser(
            "fmove", aliases=["mv", "fmv"], help="Move and rename files")
        parser_move.add_argument("source_virtual_path", help="Source existing file or dir in the luggage")
        parser_move.add_argument("target_virtual_path", help="Destination path")
        parser_move.set_defaults(func=move, luggage=luggage)

        parser_delete = command_subparsers.add_parser(
            "fdelete", aliases=["rm", "frm"], help="Delete dirs or files")
        parser_delete.add_argument(
            "virtual_path", help="Path to an existing file or directory, which is to be removed. "
                                 "Dirs are removed recursively.")
        parser_delete.set_defaults(func=delete, luggage=luggage)

        parser_quit = command_subparsers.add_parser(
            "quit", aliases=["exit"], help="Exit the Luggage prompt")
        parser_quit.set_defaults(func=exit_luggage, luggage=luggage)

        parser_help = command_subparsers.add_parser("help", help="Show this help")
        parser_help.set_defaults(func=lambda options: command_parser.print_help(), luggage=luggage)

        index = 0
        speed = 1
        session = prompt_toolkit.PromptSession()
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
                try:
                    command_options = command_parser.parse_args(commands)
                except SystemExit as ex:
                    continue
                if command_options.command is None:
                    continue

                try:
                    command_options.func(command_options)
                except Exception as ex:
                    raise ex
                    print(f"{type(ex).__name__}: {ex}{'.' if not str(ex).endswith('.') else ''}")
            except KeyboardInterrupt:
                exit_luggage()
    finally:
        luggage.close()
