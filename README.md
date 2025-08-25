# File Encryption Tool

## Dependencies

Use OpenSSL for secure algorithm implementations (AES, GCM, PBKDF2, etc.)

## Workflows

### Encryption
1. User provides the path to a file and a password
2. Generate a random encryption key (AES-256, 32 bytes)
3. Derive a key-encryption key from the user's password using PBKDF2 and a random salt
    - Make note of and document the fact that something like Argon2 would be better, but not used for sake of ease of implementation
4. Encrypt the file encryption key with the key encryption key using AES-GCM
5. Save the encrypted key and salt to a `.key` file
6. Encrypt the file using the random file encryption key

### Decryption
1. User provides the path to an encrypted file and their password
2. Derive the key encryption key with PBKDF2 and salt
3. Decrypt the file encryption key
4. Decrypt the file using the recovered key

## Key Generation

The linux `/dev/urandom` pseudo-random number generator (PRNG) is used to generate cryptographically secure, high-entropy, unpredictable bytes that are suitable for keys, nonces, and salts
> NOTE: I'm going to use OpenSSL's RAND_bytes() call to do this, but they hit /dev/urandom behind the scenes
