# Changelog for the cryptoluggage3 project

## v3.1.4 - Current development version

- Added comprehensive documentation into the README.md file.
- Added the `passgen` command to generate strong passwords.
- The `ls` and `tree` commands now filter based on the full path, not just the filename.
- The `qr` command is now aware of invalid usage (too many parameters).

## v3.1.3 - 2025/12/31

- migrated from filelock to portalocker to avoid needing a sidecar .lock file
- added extra integrity checks when opening a luggage
- ensured luggage closure (and locking release) when a bad password is provided
- fixed bug that prevented new secrets from being added (oops!)

## v3.1.2 - 2025/12/14

### New features
- Added command `passwd` to chagne a Luggage's passphrase.
- Added command `es`/`esecrets` to export all secrets into a unencrypted CSV file 
  (`is` command can import this format).

### Enhancements
- The `qr` command now accepts a filter parameter.
- The `icp` command now refuses to overwrite existing secret files; offers manual deletion instead.
- The `icp` command now supports non-broken symlinks.
- Improved filtering of secret files with `ls`: automatic wildcard addition and case insensitivity.
- Normalized the command syntax shown by `help`.
- Enhanced user feedback (including using messages instead of exceptions) in several commands.

### Bug fixes
- Fixed `mv` to prevent overwriting existing secret files, or moving dirs into their own subdirs.
- Trying to access a forbidden file now shows a clear error message instead of a traceback.
- Trying to insert nonexistent paths now shows a clear error message instead of a traceback.