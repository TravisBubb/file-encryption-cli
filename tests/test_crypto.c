#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(expr, msg)                                                      \
  do {                                                                         \
    if (!(expr)) {                                                             \
      printf("FAILED: %s\n", msg);                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

// ------------------- Helper -------------------

static int compare_buffers(const uint8_t *a, const uint8_t *b, size_t len) {
  return memcmp(a, b, len) == 0;
}

// ------------------- Positive Tests -------------------

int test_fek_generation(void) {
  CryptoContext ctx1, ctx2;
  crypto_init(&ctx1);
  crypto_init(&ctx2);

  ASSERT(crypto_generate_fek(&ctx1) == 0, "FEK generation failed (ctx1)");
  ASSERT(crypto_generate_fek(&ctx2) == 0, "FEK generation failed (ctx2)");
  ASSERT(ctx1.has_fek && ctx2.has_fek, "FEK flags not set");
  ASSERT(!compare_buffers(ctx1.fek, ctx2.fek, CRYPTO_KEY_LEN),
         "FEKs should be unique");

  crypto_cleanup(&ctx1);
  crypto_cleanup(&ctx2);
  return 0;
}

int test_kek_derivation(void) {
  CryptoContext ctx1, ctx2;
  crypto_init(&ctx1);
  crypto_init(&ctx2);

  const char *password = "mypassword";
  memset(ctx1.salt, 0xAA, CRYPTO_SALT_LEN);
  memcpy(ctx2.salt, ctx1.salt, CRYPTO_SALT_LEN);

  ASSERT(crypto_derive_kek(&ctx1, password, strlen(password), 1000) == 0,
         "KEK derivation failed (ctx1)");
  ASSERT(crypto_derive_kek(&ctx2, password, strlen(password), 1000) == 0,
         "KEK derivation failed (ctx2)");
  ASSERT(compare_buffers(ctx1.kek, ctx2.kek, CRYPTO_KEY_LEN), "KEKs mismatch");

  crypto_cleanup(&ctx1);
  crypto_cleanup(&ctx2);
  return 0;
}

int test_wrap_unwrap(void) {
  CryptoContext ctx1, ctx2;
  crypto_init(&ctx1);
  crypto_init(&ctx2);

  const char *password = "secret";
  uint8_t wrapped[64];
  size_t wrapped_len = sizeof(wrapped);

  ASSERT(crypto_generate_fek(&ctx1) == 0, "FEK gen failed");
  memset(ctx1.salt, 0xBB, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx1, password, strlen(password), 1000) == 0,
         "KEK deriv failed");
  ASSERT(crypto_wrap_file_key(&ctx1, wrapped, &wrapped_len) == 0,
         "Wrap FEK failed");

  memcpy(ctx2.salt, ctx1.salt, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx2, password, strlen(password), 1000) == 0,
         "KEK deriv failed (ctx2)");
  ASSERT(crypto_unwrap_file_key(&ctx2, wrapped, wrapped_len) == 0,
         "Unwrap FEK failed");

  ASSERT(compare_buffers(ctx1.fek, ctx2.fek, CRYPTO_KEY_LEN),
         "FEK mismatch after unwrap");

  crypto_cleanup(&ctx1);
  crypto_cleanup(&ctx2);
  return 0;
}

int test_encrypt_decrypt(void) {
  CryptoContext ctx_enc, ctx_dec;
  crypto_init(&ctx_enc);
  crypto_init(&ctx_dec);

  const char *password = "mypassword";
  uint8_t wrapped[64];
  size_t wrapped_len = sizeof(wrapped);

  uint8_t plaintext[] = "Hello, Crypto!";
  uint8_t ciphertext[sizeof(plaintext) + CRYPTO_TAG_LEN];
  size_t ct_len = sizeof(ciphertext);
  uint8_t decrypted[sizeof(plaintext)];
  size_t pt_len = sizeof(decrypted);

  ASSERT(crypto_generate_fek(&ctx_enc) == 0, "FEK gen failed");
  memset(ctx_enc.salt, 0xCC, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx_enc, password, strlen(password), 1000) == 0,
         "KEK deriv failed");
  ASSERT(crypto_wrap_file_key(&ctx_enc, wrapped, &wrapped_len) == 0,
         "Wrap FEK failed");
  ASSERT(crypto_encrypt(&ctx_enc, plaintext, sizeof(plaintext), ciphertext,
                        &ct_len) == 0,
         "Encrypt failed");

  memcpy(ctx_dec.salt, ctx_enc.salt, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx_dec, password, strlen(password), 1000) == 0,
         "KEK deriv failed");
  ASSERT(crypto_unwrap_file_key(&ctx_dec, wrapped, wrapped_len) == 0,
         "Unwrap FEK failed");
  memcpy(ctx_dec.nonce, ctx_enc.nonce, CRYPTO_NONCE_LEN);
  memcpy(ctx_dec.tag, ctx_enc.tag, CRYPTO_TAG_LEN);

  ASSERT(crypto_decrypt(&ctx_dec, ciphertext, ct_len, decrypted, &pt_len) == 0,
         "Decrypt failed");
  ASSERT(compare_buffers(plaintext, decrypted, sizeof(plaintext)),
         "Decrypted plaintext mismatch");

  crypto_cleanup(&ctx_enc);
  crypto_cleanup(&ctx_dec);
  return 0;
}

// ------------------- Negative / Edge Tests -------------------

int test_unwrap_with_wrong_kek(void) {
  CryptoContext ctx1, ctx2;
  crypto_init(&ctx1);
  crypto_init(&ctx2);

  uint8_t wrapped[64];
  size_t wrapped_len = sizeof(wrapped);
  const char *pwd1 = "pwd1", *pwd2 = "pwd2";

  ASSERT(crypto_generate_fek(&ctx1) == 0, "FEK gen failed");
  memset(ctx1.salt, 0xDD, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx1, pwd1, strlen(pwd1), 1000) == 0,
         "KEK deriv failed");
  ASSERT(crypto_wrap_file_key(&ctx1, wrapped, &wrapped_len) == 0,
         "Wrap FEK failed");

  memset(ctx2.salt, 0xDD, CRYPTO_SALT_LEN);
  ASSERT(crypto_derive_kek(&ctx2, pwd2, strlen(pwd2), 1000) == 0,
         "Wrong KEK deriv");
  ASSERT(crypto_unwrap_file_key(&ctx2, wrapped, wrapped_len) != 0,
         "Unwrap should fail with wrong KEK");

  crypto_cleanup(&ctx1);
  crypto_cleanup(&ctx2);
  return 0;
}

// ------------------- Main -------------------

typedef struct {
  const char *name;
  int (*func)(void);
} TestCase;

int main(void) {
  TestCase tests[] = {
      {"FEK generation", test_fek_generation},
      {"KEK derivation", test_kek_derivation},
      {"Wrap/unwrap FEK", test_wrap_unwrap},
      {"Encrypt/decrypt", test_encrypt_decrypt},
      {"Unwrap with wrong KEK", test_unwrap_with_wrong_kek},
  };

  int fail_count = 0;
  int num_tests = sizeof(tests) / sizeof(tests[0]);

  for (int i = 0; i < num_tests; i++) {
    printf("Running test: %s ... ", tests[i].name);
    int result = tests[i].func();
    if (result == 0) {
      printf("✅ Passed\n");
    } else {
      printf("❌ Failed\n");
      fail_count++;
    }
  }

  printf("\nSummary: %d/%d tests passed.\n", num_tests - fail_count, num_tests);
  return (fail_count == 0) ? 0 : 1;
}
