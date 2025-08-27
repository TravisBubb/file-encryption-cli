#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @file crypto.h
 * @brief AES-256-GCM encryption/decryption and key wrapping utilities.
 *
 * All functions operate on memory buffers. The caller is responsible for I/O.
 * Uses OpenSSL EVP interface under the hood.
 */

/**
 * @brief Fixed crypto parameter sizes.
 */
enum {
  CRYPTO_KEY_LEN = 32,   // 256-bit AES key
  CRYPTO_SALT_LEN = 16,  // PBKDF2 salt
  CRYPTO_NONCE_LEN = 12, // AES-GCM nonce (IV)
  CRYPTO_TAG_LEN = 16    // AES-GCM authentication tag
};

/**
 * @struct CryptoContext
 * @brief Holds the cryptographic state for a file.
 *
 * This context stores the file encryption key (FEK), derived key (KEK),
 * salt, nonce, and tag. It is fully responsible for zeroizing sensitive data
 * when cleaned up.
 *
 * All encryption/decryption operations will use this context, so the caller
 * does not need to pass keys or other secret parameters explicitly.
 */
typedef struct {
  uint8_t fek[CRYPTO_KEY_LEN];     ///< File encryption key
  uint8_t kek[CRYPTO_KEY_LEN];     ///< Derived key encryption key
  uint8_t salt[CRYPTO_SALT_LEN];   ///< PBKDF2 salt
  uint8_t nonce[CRYPTO_NONCE_LEN]; ///< AES-GCM IV for current operation
  uint8_t tag[CRYPTO_TAG_LEN];     ///< AES-GCM authentication tag
  bool has_fek; ///< True if FEK has been generated or unwrapped
  bool has_kek; ///< True if KEK has been derived
} CryptoContext;

/**
 * @brief Initializes a CryptoContext by zeroing it out.
 *
 * @param ctx Pointer to a CryptoContext to initialize.
 *
 * Must be called before any other operations on this context.
 */
void crypto_init(CryptoContext *ctx);

/**
 * @brief Cleans a CryptoContext by zeroizing sensitive data.
 *
 * @param ctx Pointer to a CryptoContext to cleanup.
 *
 * Call this when finished with the context to prevent key leakage.
 */
void crypto_cleanup(CryptoContext *ctx);

/**
 * @brief Generate a random file encryption key (FEK) and store it in ctx.
 *
 * @param ctx Pointer to an allocated CryptoContext.
 * @return 0 on success, non-zero on error.
 */
int crypto_generate_fek(CryptoContext *ctx);

/**
 * @brief Derive a key encryption key (KEK) from a password using
 * PBKDF2-HMAC-SHA256.
 *
 * @param ctx Pointer to a CryptoContext containing a salt.
 * @param password User-supplied password.
 * @param password_len Length of the password in bytes.
 * @param interations Number of PBKDF2 iterations.
 * @returns 0 on success, non-zero on error.
 *
 * @note This implementation uses PBKDF2-HMAC-SHA256.
 *       Argon2 should be considered as a stronger alternative, more resistant
 *       to GPU/ASIC cracking.
 */
int crypto_derive_kek(CryptoContext *ctx, const char *password,
                      size_t password_len, unsigned int iterations);

/**
 * @brief Encrypt (wrap) the file encryption key with the derived key encryption
 * key.
 *
 * @param ctx Pointer to CryptoContext (must have FEK and KEK).
 * @param out Buffer to hold wrapped key.
 * @param outlen On input, size of out; on output, number of bytes written.
 * @return 0 on success, non-zero on error.
 */
int crypto_wrap_file_key(CryptoContext *ctx, uint8_t *out, size_t *outlen);

/**
 * @brief Decrypt (unwrap) a wrapped FEK using the derived KEK.
 *
 * @param ctx Pointer to a CryptoContext (must have KEK).
 * @param int Wrapped key buffer.
 * @param inlen Length of the wrapped key.
 * @return 0 on success, non-zero on error.
 *
 * After this call, ctx->fek will contain the decrypted file encryption key.
 */
int crypto_unwrap_file_key(CryptoContext *ctx, const uint8_t *in, size_t inlen);

/**
 * @brief Encrypt data using AES-256-GCM with the file encryption key.
 *
 * @param ctx Pointer to CryptoContext (must have FEK).
 * @param in Input plaintext buffer.
 * @param inlen Length of plaintext.
 * @param out Output buffer for ciphertext (must be >= inlen + CRYPTO_TAG_LEN).
 * @param outlen On input, size of out; on output, bytes written.
 * @return 0 on success, non-zero on failure.
 *
 * This function updates ctx->nonce and ctx->tag for use in decryption.
 */
int crypto_encrypt(CryptoContext *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen);

/**
 * @brief Decrypt data using AES-256-GCM with the file encryption key.
 *
 * @param ctx Pointer to CryptoContext (must have FEK, nonce, and tag).
 * @param in Input ciphertext buffer (includes tag at the end).
 * @param inlen Length of ciphertext buffer.
 * @param out Output buffer for plaintext (must be >= inlen - CRYPTO_TAG_LEN).
 * @param outlen On input, size of out; on output, bytes written.
 * @return 0 on success, non-zero on failure.
 */
int crypto_decrypt(CryptoContext *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen);

#endif // CRYPTO_H
