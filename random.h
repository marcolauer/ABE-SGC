#ifndef MASTER_RANDOM_H
#define MASTER_RANDOM_H

#include <vector>

// This header file contains a few functions for generating random byte sequences.

/**
 * Generates a byte vector with random content.
 * @param[in] length the length of the byte vector.
 * @returns the byte vector.
 */
std::vector<unsigned char> byte_vector_random(int length);

/**
 * Allocates a new byte array with random content.
 * @param[in] length the length of the byte array.
 * @returns a pointer to the byte array.
 */
unsigned char *bytes_new_random(int length);

/**
 * Fills a byte array with random content.
 * @param[out] data a pointer to the byte array.
 * @param[in] length the length of the byte array.
 */
void bytes_random(unsigned char *data, int length);

#endif //MASTER_RANDOM_H
