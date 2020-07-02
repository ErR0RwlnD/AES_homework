#ifndef CMAC_H
#define CMAC_H

#include "aes.h"

#define const_Bsize 16

void *AES_cmac(unsigned char *in, unsigned int length,
                        unsigned char *out, unsigned char *key);
bool verify_mac(unsigned char *in, unsigned int length, unsigned char *out,
                unsigned char *key);

void GenerateSubkey(unsigned char *key, unsigned char *K1, unsigned char *K2);

#endif  