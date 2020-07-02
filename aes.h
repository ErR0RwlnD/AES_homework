#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#ifndef CBC
#define CBC 1
#endif

#ifndef ECB
#define ECB 1
#endif

#define AES_BLOCKLEN 16
#define AES_KEYLEN 16
#define AES_keyExpSize 176

struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1))
    uint8_t Iv[AES_BLOCKLEN];
#endif
};

typedef uint8_t state_t[4][4];
typedef enum { true = 1, false = 0 } bool;

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);
void AES_init_ctx_iv(struct AES_ctx *ctx, const uint8_t *key,
                     const uint8_t *iv);
void AES_ctx_set_iv(struct AES_ctx *ctx, const uint8_t *iv);

void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);
void AES_ECB_decrypt(const struct AES_ctx *ctx, uint8_t *buf);
void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

// only for cmac
void AES_encrypt(uint8_t *in, uint8_t *out, uint8_t *key);

#endif