# cryptoluggage

Cryptoluggage allows you to store your secrets (for example, passwords)
and private files encrypted inside a single, portable file.

Cryptoluggage itself has been tested on Linux and, to a lesser extent, on Windows and MacOS.

## Installation

`pip install cryptoluggage`

## Creating and opening Luggages:

Luggages are created an opened from the CLI using the `create` and `open` commands of the `cl` tool.
The `cl` tool is an alias for `python -m cryptoluggage`, so both commands are equivalent.

### Create and open a new Luggage at `<luggage_path>` from the CLI

`cl create <luggage_path>`

Example:

```
cl create test.lug
Passphrase: 
Confirm passphrase: 
◐ Luggage ◑
```

### Open an existing Luggage at `<luggage_path>` from the CLI

`cl open <luggage_path>`

Example:

```
cl open test.lug
Passphrase: 
◐ Luggage ◑ 
```

## Using secrets within an open Luggage

Luggages can contain any number of secret texts, each identified by a unique name.
These secrets are stored encrypted within the Luggage file, and may contain 
passwords, recovery tokens, or any other sensitive information you wish to keep safe.

Once a Luggage is opened with `cl open` (or `cl create`), you can use the following commands
within the Luggage prompt to manage your secrets:

### Create a new secret in an open Luggage

Use `sset <secret_name>` to edit a secret with name `<secret_name>` (spaces allowed), or create it if it does not exist.
Once in edit mode, type the contents of the secret. When done, press the Escape key followed by Enter to save the
secret,
or Ctrl+C to cancel the operation.

Example:

```
◐ Luggage ◑ sset my dark secret
Editing secret 'my dark secret'. ESC,Enter to save. Ctrl+C to cancel.
 
I don't want anyone else to know about this...

◐ Luggage ◑ sset github recovery tokens
Editing secret 'github recovery tokens'. ESC,Enter to save. Ctrl+C to cancel.
 
1234-4567-7890
5555-4444-6666
```

### List all secrets within the opened Luggage

Use `sls` to list all secrets stored in the opened Luggage.
You may use `sls <filter>` to filter the list of secrets whose name contains `<filter>` (case insensitive).

Note that the provided list includes their indices within brackets (e.g., `[0]`, `[1]`, etc.),
which can be used by other commands (e.g., `sset`, `scat`, etc.) to refer to secrets by index instead of by name.

Example:

```
◐ Luggage ◑ sls
[0] github recovery tokens
[1] my dark secret

◐ Luggage ◑ sls dark
[1] my dark secret

◐ Luggage ◑ sls nonexistent
No secrets found matching filter 'nonexistent'.
```

### Show the contents of a secret within the opened Luggage

Use `scat <secret_name>` to show the contents of that secret. You must provide the full name of the secret,
or alternative its index as shown by `sls`.

Example:

```
◐ Luggage ◑ scat github recovery tokens
1234-4567-7890
5555-4444-6666

◐ Luggage ◑ scat github
Secret 'github' not found.

◐ Luggage ◑ sls
[0] github recovery tokens
[1] my dark secret

◐ Luggage ◑ scat 0
Showing secret 'github recovery tokens':
1234-4567-7890
5555-4444-6666

◐ Luggage ◑ scat 1
Showing secret 'my dark secret':
I don't want anyone else to know about this...
```

### Show the contents of a secret, and also display a qr code for passwords

Sometimes, you may want to store a complicated password as a secret and then use it in your phone.
To facilitate this, you can use the `qr <secret_name>` command to both show the contents of the secret 
and display a QR code representing the password within. This way, you can easily scan the QR code with 
your phone camera to retrieve the password without needing to type it manually.

By default, the `qr` command shows the QR code for whatever appears after each `pass: ` line in the secret,
although that can also be configured. 

Note that for secrets containing spaces in their names, you will need to quote the name or use its index:

Example:

First create the secret and get its index:

```
◐ Luggage ◑ sset example.org credentials
Editing secret 'example.org credentials'. ESC,Enter to save. Ctrl+C to cancel.
 
user: myuser
pass: Ncgihyqa8BCwVchCP)eZGy)Byhd#ONH!

◐ Luggage ◑ sls example.org
[0] example.org credentials
```

Then use the `qr` command to display the QR code (using a screenshot here to show the expected formatting):

![QR screenshot](doc/qr_screenshot.png)

### Generate a strong password

You can use the `passgen <length=32> <type='full'>` command to generate a strong random password 
of the specified length and type. The generated password is simply displayed on the screen (you can then
copy it and paste it wherever you need it, e.g., into a new secret using `sset`).

Example:

```
◐ Luggage ◑ passgen
pass: m8WjV&^!9*3Wi9@ERUWnJmVSGlu={6p9

◐ Luggage ◑ passgen 64
pass: $ByC]8D)S5g&W0^N{o7q=@+h]=sd*2_dJ4DqIyf#KFPB(ahY(CtgxxfL)XUN@3TU

◐ Luggage ◑ passgen 8 alpha
pass: kw8iYbCV
```

### More commands to manipulate secrets

You can use the `help` command to get a list of all available commands within an opened Luggage.
These include:

- `srm <secret_name>`: Remove the specified secret.
- `smv <old_name> <new_name>`: Rename a secret from `<old_name>` to `<new_name>`.
- `esecrets <output_csv_path>`: Export all secrets to an unencrypted CSV file at `<output_csv_path>`.
- `isecrets <input_csv_path>`: Import secrets from an unencrypted CSV file at `<input_csv_path>`.

## Using encrypted files within an open Luggage

Luggages can also contain an encrypted file system structure, allowing you to store private files and directories
within the Luggage. Each file is stored encrypted, and so is the structure of directories and file names.
Once a Luggage is opened with `cl open` (or `cl create`), you can use the following commands
within the Luggage prompt to manage your encrypted files:

### Import existing files from disk into the opened Luggage

Use `icp <source_path> <luggage_dest_path>` to import a file or directory from your local disk 
into the opened Luggage. Here, `<source_path>` is the path on your local disk, and `<luggage_dest_path>` is the
destination path within the Luggage where the file or directory will be stored.

The original file or directory at `<source_path>` remains unchanged on your local disk after the import,
while a new encrypted copy is created within the Luggage at `<luggage_dest_path>`.

The syntax and semantics of `icp` are similar to the Unix `cp` command, considering that `<luggage_dest_path>`
refers to a path within the Luggage's encrypted file system (the root being `/`).

Example, to import a file `~/tmp/my_secret_file.txt` from your local disk into a new file `/supersecret.txt` 
within the opened Luggage, you can do:

```
◐ Luggage ◑ icp ~/tmp/my_secret_file.txt /supersecret.txt
```

You can import any file type (even complete directories) using `icp`, and you can specify the destination path
within the Luggage as needed:

```
◐ Luggage ◑ icp ~/tmp/another_secret.png /img/necronomicon.png

◐ Luggage ◑ icp ~/tmp/confidential_dir /topsecret/confidential
```

### List files and directories within the opened Luggage

Use `ls` or `tree` to list the files and directories stored within the opened Luggage.

You can also use `ls <filter>` or `tree <filter>` to filter the list of files and directories 
whose name contains `<filter>` (case insensitive). 

Example:

```
◐ Luggage ◑ ls
[test.lug]
/topsecret/
/topsecret/confidential/
/topsecret/confidential/confidential_dir/
/topsecret/confidential/confidential_dir/c.zip
/topsecret/confidential/confidential_dir/b.doc
/topsecret/confidential/confidential_dir/a.txt
/supersecret.txt
/img/
/img/necronomicon.png

◐ Luggage ◑ ls conf
[test.lug]
/topsecret/confidential/
/topsecret/confidential/confidential_dir/
/topsecret/confidential/confidential_dir/c.zip
/topsecret/confidential/confidential_dir/b.doc
/topsecret/confidential/confidential_dir/a.txt

◐ Luggage ◑ tree png
[test.lug]
 +-[img/]
    +---necronomicon.png 
```

### Extract files from the opened Luggage to disk

Use `ecp <luggage_source_path> <dest_path>` to extract a file or directory from the opened Luggage.
The Luggage remains unmodified, and a decrypted copy of the specified file or directory is created at `<dest_path>` 
on your local disk.

Example:

```
◐ Luggage ◑ ecp /supersecret.txt ~/Desktop/dontlookatme.txt
Exporting supersecret.txt into /home/user/Desktop/dontlookatme.txt...

◐ Luggage ◑ ecp / ~/tmp/all_luggage_files
Exporting / into /home/user/tmp/all_luggage_files...
```

### More commands to manipulate files within the opened Luggage

You can use the `help` command to get a list of all available commands within an opened Luggage.
These include:

- `rm <luggage_path>`: Remove the specified file or directory from the Luggage.
- `mv <old_luggage_path> <new_luggage_path>`: Rename or move a file or directory within the Luggage.

## Managing and backing up Luggages

### Change the passphrase of an open Luggage

You can change the passphrase protecting an open Luggage using the `passwd` command from the Luggage prompt.
This command will prompt you to enter a new passphrase, and then it will re-encrypt all data within the Luggage
(you will need the previous passphrase to open the Luggage, but not to change it).

Example:

```
◐ Luggage ◑ passwd
You are about to change the luggage's passphrase. It is recommended you back up your original luggage first (this tool will not do it for you).
New passphrase: 
Repeat new passphrase: 
Passphrase changed successfully.
```

### Export all secrets to an unencrypted CSV file

You can export all secrets stored within an open Luggage to an unencrypted CSV file using the 
`esecrets <output_csv_path>` command from the Luggage prompt. This command 
will create a headerless CSV file at `<output_csv_path>` containing all secrets, 
with two columns (secret name and content).

You can later import this CSV file into the same or another Luggage using the `isecrets <input_csv_path>` command.

Example:

```
◐ Luggage ◑ esecrets ~/tmp/secrets.csv

◐ Luggage ◑ quit
Bye

$ cat ~/tmp/secrets.csv
"example.org credentials","user: myuser
pass: Ncgihyqa8BCwVchCP)eZGy)Byhd#ONH!"
"github recovery tokens","1234-4567-7890
5555-4444-6666"
"my dark secret","I don't want anyone else to know about this..."
```

### Export all files from the Luggage to disk

You can use the `ecp / <path>` command from the Luggage prompt to export all files and directories 
stored within the opened Luggage to a specified destination path `<path>` on your local disk.

You can then import them back into the same or another Luggage using the `icp <path> <luggage_dest_path>` command.

Example:

```
◐ Luggage ◑ ecp / ~/tmp/full_file_backup
Exporting / into /home/user/tmp/full_file_backup...
```

## Security model

Cryptoluggage uses strong encryption (AES-256 in CBC mode) to protect your data.
The encryption key is derived from your passphrase using PBKDF2 with a high iteration count (1 million by default)
and a random salt (24 bytes by default). This makes brute-force attacks computationally expensive, and very difficult
for sufficiently strong passphrases.
Random IVs are used for each encryption operation to ensure that identical plaintexts
produce different ciphertexts, further enhancing security.

### Luggage structure

Each Luggage is a sqlite3 database with a single table `token_store` containing 2 columns, `id` and `token`.
The `id` field is an integer that identifies the contents of the `token` field, and `token` is a blob that
contains the secret data.

IDs `-3`, `-2` and `-1` are always present:

* `-1`: The Luggage's cryptographic parameters. These include a random salt and the number of iterations
  used to derive the master cryptographic key from the user's passphrase. By default, PBKDF2 with 1 million iterations
  and a 24-byte random salt are used.

  **Notes**:
    * This entry is the only one not encrypted; these parameters are not secret and they are needed to perform
      decryption.
    * From version 3.1.0 onwards, this field is stored in JSON format. In previous versions,
      it was stored using pickle, which could be dangerous if the database file was tampered with. You can load Luggages
      created with older versions using the `--legacy` flag when opening them, but beware of the security implications
      if the file integrity cannot be guaranteed.
    * Versions prior to 3.1.0 used a salt length of 16 bytes, which was deemed safe enough by OWASP. The salt length
      is not automatically updated when opening an older Luggage.

* `-2`: The Luggage's secret texts. Each secret has a unique name associated with it, and arbitrary UTF-8 contents.
  The `token` field contains an encrypted representation of all secrets, structured as a dictionary indexed by name.
  Encryption of this secret dictionary is performed using the master cryptographic key. Each time the secrets are
  updated, a new random IV is generated for encryption.

  **Notes**:
    * Attackers with access to this field can infer the total amount of secret information, but not the number of
      secrets, their names or contents.
    * Internally, pickle is used to store the dictionary of secrets. However,
        * decryption (and thus pickle.loads) is only performed after successful HMAC verification, so the integrity of
          the data is guaranteed. Thus, an attacker that tampers with this field cannot trigger arbitrary code execution
          without knowing the passphrase or encryption key.
        * From version 3.1.0 onwards, even if the passphrase is compromised, arbitrary code execution is made more
          difficult by using a custom restricted unpickler.

* `-3`: The Luggage's secret file system structure. A tree of Dirs and leaf Files is stored here,
  representing the files and directories in the Luggage. Each File and Directory has a name, and Files have arbitrary
  binary contents. This entry contains only the structure of the file system (i.e., names and hierarchy), while the
  actual contents of each File are stored in separate DB entries (those with positive IDs).
  Encryption of this structure is performed using the master cryptographic key. Each time the structure is altered,
  a new random IV is generated for encryption.
