#include "relic_util.h"
#include <iostream>
#include <limits>
#include <mbedtls/sha256.h>

void bn_util_set_int_mod(bn_t c, const int i, const bn_t m) {
    if (i > std::numeric_limits<dig_t>::max() || -i > std::numeric_limits<dig_t>::max()) {
        std::cerr << "The integer is larger than dig_t from the RELIC toolkit" << std::endl;
        exit(-1);
    }
    if (i >= 0) {
        bn_set_dig(c, i);
        return;
    }
    bn_set_dig(c, -i);
    bn_util_neg_mod(c, c, m);
}

void bn_util_add_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_add(c, a, b);
    bn_mod(c, c, m);
}

void bn_util_sum_mod(bn_t c, const bn_t *as, const int n, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_copy(temp, as[0]);
    for (int i = 1; i < n; ++i) {
        bn_util_add_mod(temp, temp, as[i], m);
    }
    bn_copy(c, temp);
    bn_free(temp);
}

void bn_util_add_int_mod(bn_t c, const bn_t a, const int i, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_util_set_int_mod(temp, i , m);
    bn_util_add_mod(c, a, temp, m);
    bn_free(temp);
}

void bn_util_sub_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_sub(c, a, b);
    bn_mod(c, c, m);
}

void bn_util_sub_int_mod(bn_t c, const bn_t a, const int i, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_util_set_int_mod(temp, i , m);
    bn_util_sub_mod(c, a, temp, m);
    bn_free(temp);
}

void bn_util_mul_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    bn_mul(c, a, b);
    bn_mod(c, c, m);
}

void bn_util_mul_int_mod(bn_t c, const bn_t a, const int i, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_util_set_int_mod(temp, i , m);
    bn_util_mul_mod(c, a, temp, m);
    bn_free(temp);
}

void bn_util_div_mod(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
    if (bn_cmp_dig(a, 1) == RLC_EQ) {
        bn_mod_inv(c, b, m);
        return;
    }
    bn_t inv;
    bn_util_null_init(inv);
    bn_mod_inv(inv, b, m);
    bn_util_mul_mod(c, a, inv, m);
    bn_free(inv);
}

void bn_util_div_int_mod(bn_t c, const bn_t a, const int i, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_util_set_int_mod(temp, i , m);
    bn_util_div_mod(c, a, temp, m);
    bn_free(temp);
}

void bn_util_mxp_int(bn_t c, const bn_t a, const int i, const bn_t m) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_util_set_int_mod(temp, i , m);
    bn_mxp(c, a, temp, m);
    bn_free(temp);
}

void bn_util_neg_mod(bn_t c, const bn_t a, const bn_t m) {
    bn_neg(c, a);
    bn_mod(c, c, m);
}

void bn_util_scalar_product(bn_t result, bn_t order, const std::vector<bn_t *>& v1, const std::vector<bn_t *>& v2) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_zero(result);
    if (v1.size() != v2.size()) {
        std::cerr << "Vector lengths do not match" << std::endl;
        exit(-1);
    }
    for (int i = 0; i < v1.size(); ++i) {
        bn_util_mul_mod(temp, *v1[i], *v2[i], order);
        bn_util_add_mod(result, result, temp, order);
    }
    bn_free(temp);
}

void bn_util_scalar_product_int(bn_t result, bn_t order, const std::vector<bn_t *>& v1, const std::vector<int>& v2) {
    bn_t temp;
    bn_util_null_init(temp);
    bn_zero(result);
    if (v1.size() != v2.size()) {
        std::cerr << "Vector lengths do not match" << std::endl;
        exit(-1);
    }
    for (int i = 0; i < v1.size(); ++i) {
        bn_util_set_int_mod(temp, v2[i], order);
        bn_util_mul_mod(temp, *v1[i], temp, order);
        bn_util_add_mod(result, result, temp, order);
    }
    bn_free(temp);
}

std::vector<bn_t *> bn_util_copy_vector(const std::vector<bn_t *>& vec) {
    std::vector<bn_t *> result;
    result.reserve(vec.size());
    for (auto ptr : vec) {
        auto ptr2 = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*ptr2);
        bn_copy(*ptr2, *ptr);
        result.push_back(ptr2);
    }
    return result;
}

void bn_util_free_vector(const std::vector<bn_t *>& vec) {
    for (const auto val : vec) {
        bn_free(*val);
        free(val);
    }
}

void g1_util_mul_int_mod(g1_t r, const g1_t p, const int i, const bn_t m) {
    bn_t a;
    bn_util_null_init(a)
    bn_util_set_int_mod(a, i , m);
    g1_mul(r, p, a);
    bn_free(a);
}

void g1_util_mul_sim_lot(g1_t r, const g1_t *as, const bn_t *bs, const int n) {
    g1_t temp, temp2;
    g1_util_null_init(temp);
    g1_util_null_init(temp2);
    g1_set_infty(temp);
    int i;
    for (i = 1; i < n; i += 2) {
        g1_mul_sim(temp2, as[i-1], bs[i-1], as[i], bs[i]);
        g1_add(temp, temp, temp2);
    }
    if (const int last = n - 1; i - 2 != last) {
        g1_mul(temp2, as[last], bs[last]);
        g1_add(temp, temp, temp2);
    }
    g1_copy(r, temp);
    g1_free(temp);
    g1_free(temp2);
}

void g2_util_mul_int_mod(g2_t r, const g2_t p, const int i, const bn_t m) {
    bn_t a;
    bn_util_null_init(a)
    bn_util_set_int_mod(a, i , m);
    g2_mul(r, p, a);
    bn_free(a);
}

void g2_util_mul_sim_lot(g2_t r, const g2_t *as, const bn_t *bs, const int n) {
    g2_t temp, temp2;
    g2_util_null_init(temp);
    g2_util_null_init(temp2);
    g2_set_infty(temp);
    int i;
    for (i = 1; i < n; i += 2) {
        g2_mul_sim(temp2, as[i-1], bs[i-1], as[i], bs[i]);
        g2_add(temp, temp, temp2);
    }
    if (const int last = n - 1; i - 2 != last) {
        g2_mul(temp2, as[last], bs[last]);
        g2_add(temp, temp, temp2);
    }
    g2_copy(r, temp);
    g2_free(temp);
    g2_free(temp2);
}

void gt_util_div(gt_t c, const gt_t a, const gt_t b){
    gt_t inv;
    gt_util_null_init(inv);
    gt_inv(inv, b);
    gt_mul(c, a, inv);
    gt_free(inv);
}

void gt_util_exp_sim_lot(gt_t r, const gt_t *as, const bn_t *bs, const int n) {
    gt_t temp, temp2;
    gt_util_null_init(temp);
    gt_util_null_init(temp2);
    gt_set_unity(temp);
    int i;
    for (i = 1; i < n; i += 2) {
        gt_exp_sim(temp2, as[i-1], bs[i-1], as[i], bs[i]);
        gt_mul(temp, temp, temp2);
    }
    if (const int last = n - 1; i - 2 != last) {
        gt_exp(temp2, as[last], bs[last]);
        gt_mul(temp, temp, temp2);
    }
    gt_copy(r, temp);
    gt_free(temp);
    gt_free(temp2);
}

std::vector<unsigned char> gt_util_to_aes_key(gt_t k, const int byte_length) {
    constexpr bool compression = false;
    // key_data_length = 12 * RLC_FP_BYTES = 576 bytes for BLS12-381
    const int key_data_length = gt_size_bin(k, compression);
    std::vector<unsigned char> key_data(key_data_length);
    gt_write_bin(key_data.data(), key_data_length, k, compression);
    std::vector<unsigned char> key(32);
    mbedtls_sha256(key_data.data(), key_data.size(), key.data(), 0);
    key.resize(byte_length);
    return key;
}