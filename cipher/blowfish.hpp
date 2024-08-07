//
// Created by mason on 2024/7/31.
//

#ifndef PDG_PARSER_BLOWFISH_HPP
#define PDG_PARSER_BLOWFISH_HPP
#pragma once
#include <cinttypes>

typedef struct {
  uint32_t P[16 + 2];
  uint32_t S[4][256];
} BLOWFISH_CTX;

void Blowfish_Init(BLOWFISH_CTX *ctx, const uint8_t *key, int32_t keyLen);
void Blowfish_Encrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);
void Blowfish_Decrypt(BLOWFISH_CTX *ctx, uint32_t *xl, uint32_t *xr);


#endif //PDG_PARSER_BLOWFISH_HPP
