//
// Created by mason on 2024/7/31.
//

#ifndef PDG_PARSER_MD5_HPP
#define PDG_PARSER_MD5_HPP
#pragma once
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest);

#endif //PDG_PARSER_MD5_HPP
