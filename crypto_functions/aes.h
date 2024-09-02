#ifndef MASTER_AES_H
#define MASTER_AES_H

#include "../util.h"
extern "C" {
#include <relic.h>
}

/**
 * Encrypts the a message together with the message length with AES-128.
 * @param[in] key_data the 128-bit key.
 * @param[in] message the message.
 * @returns the ciphertext.
 */
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key_data, const std::vector<unsigned char>& message);

/**
 * Encrypts the a message together with the message length with AES-128.
 * @param[in] key_data the 128-bit key.
 * @param[in] message the message.
 * @param[in] length the message length.
 * @returns the ciphertext.
 */
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& key_data, const unsigned char *message, int length);

/**
 * Decrypts a ciphertext containing the message and the original message length with AES-128.
 * @param[in] key_data the 128-bit key.
 * @param[in] ciphertext the ciphertext.
 * @return the original message.
 */
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key_data, const std::vector<unsigned char>& ciphertext);

/**
 * Decrypts a ciphertext containing the message and the original message length with AES-128.
 * @param[in] key_data the 128-bit key.
 * @param[in] ciphertext the ciphertext.
 * @param[in] length the ciphertext length.
 * @return the original message.
 */
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& key_data, const unsigned char *ciphertext, int length);

#endif //MASTER_AES_H
