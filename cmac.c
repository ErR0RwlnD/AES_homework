#include "cmac.h"
#include "aes.h"
#include <stdlib.h>
#include <string.h>

void block_xor(uint8_t *dst, uint8_t *a, uint8_t *b) {
    for (int j = 0; j < 16; j++) {
        dst[j] = a[j] ^ b[j];
    }
}

void block_leftshift(uint8_t *dst, uint8_t *src) {
    uint8_t ovf = 0x00;
    for (int i = 15; i >= 0; i--) {
        dst[i] = src[i] << 1;
        dst[i] |= ovf;
        ovf = (src[i] & 0x80) ? 1 : 0;
    }
}

void *AES_cmac(uint8_t *in, unsigned int length, uint8_t *out,
                  uint8_t *key) {
    uint8_t *K1;
    uint8_t *K2;
    K1 = (uint8_t *)malloc(16);
    K2 = (uint8_t *)malloc(16);
    GenerateSubkey(key, K1, K2);

    int n = (length / const_Bsize);
    bool flag = false;
    if (length % const_Bsize != 0) {
        n++;
    }

    if (n == 0) {
        n = 1;
    } else if (length % const_Bsize == 0) {
        flag = true;
    }

    uint8_t M[n][const_Bsize];
    memset(M[0], 0, n * const_Bsize);
    memcpy(M[0], in, length);
    if (!flag) {
        memset(M[0] + length, 0x80, 1);
    }
    if (flag) {
        block_xor(M[n - 1], M[n - 1], K1);
    } else {
        block_xor(M[n - 1], M[n - 1], K2);
    }

    uint8_t X[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t Y[const_Bsize];

    for (int i = 0; i < n - 1; i++) {
        block_xor(Y, M[i], X);
        AES_encrypt(Y, X, key);
    }
    block_xor(Y, M[n - 1], X);
    AES_encrypt(Y, out, key);
    free(K1);
    free(K2);
}

bool verify_mac(uint8_t *in, unsigned int length, uint8_t *out, uint8_t *key) {
    bool flag = true;
    uint8_t result[16];
    AES_cmac(in, length, (uint8_t *)result, key);
    for (int i = 0; i < const_Bsize; i++) {
        if (!(result[i] ^ out[i])) {
            flag = false;
            break;
        }
    }
    return flag;
}

void GenerateSubkey(uint8_t *key, uint8_t *K1, uint8_t *K2) {
    uint8_t L[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t const_Rb[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    AES_ECB_encrypt(&ctx, L);

    block_leftshift(K1, L);
    if (L[0] & 0x80) {
        block_xor(K1, K1, const_Rb);
    }

    block_leftshift(K2, K1);
    if (K1[0] & 0x80) {
        block_xor(K2, K2, const_Rb);
    }
}