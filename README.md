# cryptoluggage

Cryptoluggage allows you to store your secrets (for example, passwords)
and private files encrypted inside a single, portable file.

Cryptoluggage itself has been tested on Linux and, to a lesser extent, on Windows.

## Installation

`pip install cryptoluggage`

## Running

After installation, you can run the `cl` command or `python -m cryptoluggage <arguments>`

## Usage:

To create a new Luggage:

`cl create luggage_path`

To open an existing Luggage:

`cl open luggage_path`

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
