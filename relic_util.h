#ifndef MASTER_RELIC_UTIL_H
#define MASTER_RELIC_UTIL_H

#include <vector>
extern "C" {
#include <relic.h>
}

// This header file contains frequently used combinations of functions from the RELIC toolkit.

/**
 * Initializes a multiple precision integer of type bn_t
 * @param[out] A the multiple precision integer.
 */
#define bn_util_null_init(A) {                                              \
    bn_null(A);                                                             \
    bn_new(A)                                                               \
}

/**
 * Assigns an integer value to a multiple precision integer modulo another multiple precision integer.
 * @param[out] c the resulting multiple precision integer.
 * @param[in] i the integer value.
 * @param[in] m the modulus.
 */
void bn_util_set_int_mod(bn_t c, int i, const bn_t m);

/**
 * Adds two multiple precision integers modulo another multiple precision integer.
 * @param[out] c the sum modulo m.
 * @param[in] a the first summand.
 * @param[in] b the second summand.
 * @param[in] m the modulus.
 */
void bn_util_add_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/**
 * Computes the sum of an array of multiple precision integers modulo another multiple precision integer.
 * @param[out] c the sum modulo m.
 * @param[in] as a pointer to the array of multiple precision integers to be summed.
 * @param[in] n the number of elements to be summed.
 * @param[in] m the modulus.
 */
void bn_util_sum_mod(bn_t c, const bn_t *as, int n, const bn_t m);

/**
 * Adds an integer value to a multiple precision integer modulo another multiple precision integer.
 * @param[out] c the sum modulo m.
 * @param[in] a the multiple precision integer.
 * @param[in] i the integer value.
 * @param[in] m the modulus.
 */
void bn_util_add_int_mod(bn_t c, const bn_t a, int i, const bn_t m);

/**
 * Subtracts two multiple precision integers from each other modulo another multiple precision integer.
 * @param[out] c the difference modulo m.
 * @param[in] a the minuend.
 * @param[in] b the subtrahend.
 * @param[in] m the modulus.
 */
void bn_util_sub_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/**
 * Subtracts an integer value from a multiple precision integer modulo another multiple precision integer.
 * @param[out] c the difference modulo m.
 * @param[in] a the multiple precision integer (minuend).
 * @param[in] i the integer value (subtrahend).
 * @param[in] m the modulus.
 */
void bn_util_sub_int_mod(bn_t c, const bn_t a, int i, const bn_t m);

/**
 * Multiplies two multiple precision integers modulo another multiple precision integer.
 * @param[out] c the product modulo m.
 * @param[in] a the multiplier.
 * @param[in] b the multiplicand.
 * @param[in] m the modulus.
 */
void bn_util_mul_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/**
 * Multiplies a multiple precision integer by an integer value modulo another multiple precision integer.
 * @param[out] c the product modulo m.
 * @param[in] a the multiple precision integer (multiplier).
 * @param[in] i the integer value (multiplicand).
 * @param[in] m the modulus.
 */
void bn_util_mul_int_mod(bn_t c, const bn_t a, int i, const bn_t m);

/**
 * Divides a multiple precision integer by another multiple precision integer modulo another multiple precision integer.
 * @param[out] c the quotient modulo m.
 * @param[in] a the dividend.
 * @param[in] b the divisor.
 * @param[in] m the modulus.
 */
void bn_util_div_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m);

/**
 * Divides a multiple precision integer by an integer value modulo another multiple precision integer.
 * @param[out] c the quotient modulo m.
 * @param[in] a the multiple precision integer (dividend).
 * @param[in] i the integer value (divisor).
 * @param[in] m the modulus.
 */
void bn_util_div_int_mod(bn_t c, const bn_t a, int i, const bn_t m);

/**
 * Exponentiates a multiple precision integer by an integer value modulo another multiple precision integer.
 * @param[out] c the power modulo m.
 * @param[in] a the multiple precision integer (base).
 * @param[in] i the integer value (exponent).
 * @param[in] m the modulus.
 */
void bn_util_mxp_int(bn_t c, const bn_t a, int i, const bn_t m);

/**
 * Negates a multiple precision integer modulo another multiple precision integer.
 * @param[out] c the result.
 * @param[in] a the value to negate.
 * @param[in] m the modulus.
 */
void bn_util_neg_mod(bn_t c, const bn_t a, const bn_t m);

/**
 * Computes the scalar product of two vectors of multiple precision integers in a finite field.
 * @param[out] result the result.
 * @param[in] order the order of the finite field.
 * @param[in] v1 the first vector of multiple precision integers.
 * @param[in] v2 the second vector of multiple precision integers.
 */
void bn_util_scalar_product(bn_t result, bn_t order, const std::vector<bn_t *>& v1, const std::vector<bn_t *>& v2);

/**
 * Computes the scalar product of one vector of multiple precision integers and one vector of integer values in a finite
 * field.
 * @param[out] result the result.
 * @param[in] order the order of the finite field.
 * @param[in] v1 the vector of multiple precision integers.
 * @param[in] v2 the vector of integer values.
 */
void bn_util_scalar_product_int(bn_t result, bn_t order, const std::vector<bn_t *>& v1, const std::vector<int>& v2);

/**
 * Copies a vector of multiple precision integers.
 * @param[in] v the vector to be copied.
 * @returns the copy.
 */
std::vector<bn_t *> bn_util_copy_vector(const std::vector<bn_t *>& vec);

/**
 * Frees all elements of a vector of multiple precision integers.
 * @param[in] v the vector.
 */
void bn_util_free_vector(const std::vector<bn_t *>& vec);

/**
 * Initializes an element of G_1.
 * @param[out] A the element of G_1.
 */
#define g1_util_null_init(A) {                                              \
    g1_null(A);                                                             \
    g1_new(A)                                                               \
}

/**
 * Performs an elliptic curve point multiplication of an element of G_1 by an integer value modulo a multiple precision
 * integer (R = (i mod m)P).
 * @param[out] r the resulting element of G_1.
 * @param[in] p the input element of G_1.
 * @param[in] i the integer value.
 * @param[in] m the modulus.
 */
void g1_util_mul_int_mod(g1_t r, const g1_t p, int i, const bn_t m);

/**
 * Computes the sum of n elements of G_1 that were multiplied by multiple precision integers in an efficient way.
 * The efficiency is achieved by always multiplying two elements of G_1 simultaneously.
 * @param[out] r	the sum.
 * @param[in] as	a pointer to the array of elements of G_1.
 * @param[in] bs a pointer to the array of multiple precision integers.
 * @param[in] n	the number of elements to be multiplied and summed.
 */
void g1_util_mul_sim_lot(g1_t r, const g1_t *as, const bn_t *bs, int n);

/**
 * Initializes an element of G_2.
 * @param[out] A the element of G_2.
 */
#define g2_util_null_init(A) {                                              \
    g2_null(A);                                                             \
    g2_new(A)                                                               \
}

/**
 * Performs an elliptic curve point multiplication of an element of G_2 by an integer value modulo a multiple precision
 * integer (R = (i mod m)P).
 * @param[out] r the resulting element of G_2.
 * @param[in] p the input element of G_2.
 * @param[in] i the integer value.
 * @param[in] m the modulus.
 */
void g2_util_mul_int_mod(g2_t r, const g2_t p, int i, const bn_t m);

/**
 * Computes the sum of n elements of G_2 that were multiplied by multiple precision integers in an efficient way.
 * The efficiency is achieved by always multiplying two elements of G_2 simultaneously.
 * @param[out] r	the sum.
 * @param[in] as	a pointer to the array of elements of G_2.
 * @param[in] bs a pointer to the array of multiple precision integers.
 * @param[in] n	the number of elements to be multiplied and summed.
 */
void g2_util_mul_sim_lot(g2_t r, const g2_t *as, const bn_t *bs, int n);

/**
 * Initializes an element of G_T.
 * @param[out] A the element of G_T.
 */
#define gt_util_null_init(A) {                                              \
    gt_null(A);                                                             \
    gt_new(A)                                                               \
}

/**
 * Divides an element of G_T by another element of G_T.
 * @param[out] c the quotient.
 * @param[in] a the dividend.
 * @param[in] b the divisor.
 */
void gt_util_div(gt_t c, const gt_t a, const gt_t b);

/**
 * Computes the product of n elements of G_T that were exponentiated by multiple precision integers in an efficient way.
 * The efficiency is achieved by always exponentiating two elements of G_T simultaneously.
 * @param[out] r	the product.
 * @param[in] as	a pointer to the array of elements of G_T.
 * @param[in] bs a pointer to the array of multiple precision integers.
 * @param[in] n	the number of elements to be exponentiated and multiplied.
 */
void gt_util_exp_sim_lot(gt_t r, const gt_t *as, const bn_t *bs, int n);

/**
 * Securely derives a cryptographic key from an element of G_T.
 * @param[in] k the element of G_T.
 * @param[in] byte_length the length of the cryptographic key to be derived
 * @returns the cryptographic key.
 */
std::vector<unsigned char> gt_util_to_aes_key(gt_t k, int byte_length);

#endif //MASTER_RELIC_UTIL_H
