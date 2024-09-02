#include "aes.h"
#include <cstdio>
#include <iostream>
#include <mbedtls/aes.h>

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key_data, const std::vector<unsigned char>& message) {
    if (key_data.size() != 16) {
        std::cout << "ERROR: key_data length != 128bit" << std::endl;
        exit(-1);
    }
    unsigned char iv[16];
    memset(iv, 0, 16);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key_data.data(), 128);
    size_t message_length = message.size();
    size_t plaintext_length = 4 + message_length;
    plaintext_length += (16 - ((int) plaintext_length % 16));
    std::vector<unsigned char> plaintext(plaintext_length);
    plaintext[0] = (message_length & 0xff000000) >> 24;
    plaintext[1] = (message_length & 0xff0000) >> 16;
    plaintext[2] = (message_length & 0xff00) >> 8;
    plaintext[3] = (message_length & 0xff);
    memcpy(plaintext.data() + 4, message.data(), message_length);
    std::vector<unsigned char> ciphertext(plaintext_length);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plaintext_length, iv, plaintext.data(), ciphertext.data());
    mbedtls_aes_free(&ctx);
    return ciphertext;
}

std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key_data, const unsigned char *message, const int length) {
    if (key_data.size() != 16) {
        std::cout << "ERROR: key_data length != 128bit" << std::endl;
        exit(-1);
    }
    unsigned char iv[16];
    memset(iv, 0, 16);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_enc(&ctx, key_data.data(), 128);
    size_t plaintext_length = 4 + length;
    plaintext_length += (16 - ((int) plaintext_length % 16));
    std::vector<unsigned char> plaintext(plaintext_length);
    plaintext[0] = (length & 0xff000000) >> 24;
    plaintext[1] = (length & 0xff0000) >> 16;
    plaintext[2] = (length & 0xff00) >> 8;
    plaintext[3] = (length & 0xff);
    memcpy(plaintext.data() + 4, message, length);
    std::vector<unsigned char> ciphertext(plaintext_length);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, plaintext_length, iv, plaintext.data(), ciphertext.data());
    mbedtls_aes_free(&ctx);
    return ciphertext;
}

std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key_data, const std::vector<unsigned char>& ciphertext) {
    if (key_data.size() != 16) {
        std::cout << "ERROR: key_data length != 128bit" << std::endl;
        exit(-1);
    }
    unsigned char iv[16];
    memset(iv, 0, 16);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key_data.data(), 128);
    std::vector<unsigned char> plaintext(ciphertext.size());
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, ciphertext.size(), iv, ciphertext.data(), plaintext.data());
    mbedtls_aes_free(&ctx);
    int message_length = ((plaintext[0]) << 24) | ((plaintext[1]) << 16) | ((plaintext[2]) << 8) | ((plaintext[3]));
    plaintext.erase(plaintext.begin(), plaintext.begin() + 4);
    plaintext.resize(message_length);
    return plaintext;
}

std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key_data, const unsigned char *ciphertext, const int length) {
    if (key_data.size() != 16) {
        std::cout << "ERROR: key_data length != 128bit" << std::endl;
        exit(-1);
    }
    unsigned char iv[16];
    memset(iv, 0, 16);
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    mbedtls_aes_setkey_dec(&ctx, key_data.data(), 128);
    std::vector<unsigned char> plaintext(length);
    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, length, iv, ciphertext, plaintext.data());
    mbedtls_aes_free(&ctx);
    int message_length = ((plaintext[0]) << 24) | ((plaintext[1]) << 16) | ((plaintext[2]) << 8) | ((plaintext[3]));
    plaintext.erase(plaintext.begin(), plaintext.begin() + 4);
    plaintext.resize(message_length);
    return plaintext;
}