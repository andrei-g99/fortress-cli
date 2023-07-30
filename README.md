![logo](https://i.imgur.com/2b8NhZj.png)

# FortressCLI
Fortress is an open source file encryption command-line tool based on the AES-256 encryption standard.

It implements the Cipher Block Chaining Mode as described in the [NIST Special Publication 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) Section 6.2.

# Encrypt/Decrypt a file
To encrypt/decrypt files, the following parameters should be used when running fortress-cli:
```bash
./path-to/fortress-cli  <encrypt/decrypt>  filename_1  filename_2  passphrase
```
For file encryption: 
- "filename_1" is the file to be encrypted
- "filename_2" is the name of the encrypted output, a BIN format is recommmended e.g. "output.bin"
- The last parameter is the passphrase used to encrypt the file

For file decryption:
- "filename_1" is the name of the decrypted output to be generated
- "filename_2" is the name of the encrypted input
- The last parameter is the passphrase used to decrypt the file (it must match the original encryption passphrase for successful decryption)

All file names should end with a format e.g. "name.format"

# Planning for release v1.0.0
Features to be implemented:
1. Integrity checks: give option to check integrity of files with checksum and signatures
2. Progress indicator while encrypting/decrypting
3. File Shredder: option to delete original file after encryption
4. Cross-platform compatibility
5. Parallel processing
6. Automated tests
7. Examples and docs

# Possible in the future
1. Steganography support
2. Time based encryption (give users the option to specify a time window in which the file can be decrypted)
3. Hardware acceleration
4. Biometric key generation
