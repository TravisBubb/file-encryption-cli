#include "crypto.h"
#include "stdint.h"
#include "stdlib.h"

void crypto_init(CryptoContext *ctx) {}
void crypto_cleanup(CryptoContext *ctx) {}
int crypto_generate_fek(CryptoContext *ctx) { return 0; }
int crypto_derive_kek(CryptoContext *ctx, const char *password,
                      size_t password_len, unsigned int iterations) {
  return 0;
}
int crypto_wrap_file_key(CryptoContext *ctx, uint8_t *out, size_t *outlen) {
  return 0;
}
int crypto_unwrap_file_key(CryptoContext *ctx, const uint8_t *in,
                           size_t inlen) {
  return 0;
}
int crypto_encrypt(CryptoContext *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen) {
  return 0;
}
int crypto_decrypt(CryptoContext *ctx, const uint8_t *in, size_t inlen,
                   uint8_t *out, size_t *outlen) {
  return 0;
}
