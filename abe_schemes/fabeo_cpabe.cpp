#include "fabeo_cpabe.h"
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include "../MSPMatrix.h"
#include "../secret_sharing.h"
#include "../relic_util.h"
#include "../serialize.h"
extern "C" {
#include <relic.h>
}

namespace fabeo_cpabe {
    void setup(master_key& mk, public_key& pk, bn_t order) {
        mk.alpha = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.alpha);
        bn_rand_mod(*mk.alpha, order);
        pk.eg1g2_alpha = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.eg1g2_alpha);
        gt_exp_gen(*pk.eg1g2_alpha, *mk.alpha);
    }

    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const master_key& mk) {
        sk.identity = identity;

        bn_t r;
        g1_t temp_g1;
        bn_util_null_init(r);
        g1_util_null_init(temp_g1);
        sk.sk1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.sk1);

        bn_add_dig(r, order, 1);
        const size_t hash_input_size = bn_size_bin(r);
        uint8_t hash_input[hash_input_size];
        bn_write_bin(hash_input, hash_input_size, r);
        g1_map(*sk.sk1, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), hash_input_size);

        bn_rand_mod(r, order);
        g1_mul(*sk.sk1, *sk.sk1, r);
        g1_mul_gen(temp_g1, *mk.alpha);
        g1_add(*sk.sk1, temp_g1, *sk.sk1);
        g1_free(temp_g1);
        for (const auto attr : identity) {
            auto sk2attr = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*sk2attr);
            g1_map(*sk2attr, static_cast<const uint8_t *>(static_cast<void *>(const_cast<int *>(&attr))), sizeof(int));
            g1_mul(*sk2attr, *sk2attr, r);
            sk.sk2[attr] = sk2attr;
        }
        sk.sk3 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.sk3);
        g2_mul_gen(*sk.sk3, r);
        bn_free(r);
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk) {
        ct.policy = policy->clone();
        ct.tau = policy->get_max_occurrence() + 1;

        MSPMatrix *msp = MSPMatrix::from_TTree(policy, order);
        const size_t rows = msp->get_rows();
        const size_t cols = msp->get_cols();
        if (cols < 1) {
            std::cerr << "FABEO CPABE: Empty MSPMatrix" << std::endl;
            exit(-1);
        }

        std::vector<bn_t *> v(cols);
        for (int i = 0; i < cols; ++i) {
            v[i] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*v[i]);
            bn_rand_mod(*v[i], order);
        }
        ct.ct1 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.ct1)
        g2_mul_gen(*ct.ct1, *v[0]);
        bn_t s_prime[ct.tau];
        ct.ct2.reserve(ct.tau);
        for (int i = 0; i < ct.tau; ++i) {
            bn_util_null_init(s_prime[i]);
            bn_rand_mod(s_prime[i], order);
            auto ct2i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*ct2i)
            g2_mul_gen(*ct2i, s_prime[i]);
            ct.ct2.push_back(ct2i);
        }

        bn_t temp;
        g1_t order_hash, temp_g1;
        bn_util_null_init(temp);
        g1_util_null_init(order_hash);
        g1_util_null_init(temp_g1);
        bn_add_dig(temp, order, 1);
        const size_t hash_input_size = bn_size_bin(temp);
        uint8_t hash_input[hash_input_size];
        bn_write_bin(hash_input, hash_input_size, temp);
        g1_map(order_hash, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), hash_input_size);
        for (int i = 0; i < rows; ++i) {
            MSPAttribute attr = msp->get_attr_from_row(i);
            std::vector<bn_t *> row = msp->get_row(i);

            auto ct3i = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*ct3i);
            g1_map(*ct3i, static_cast<const uint8_t *>(static_cast<void *>(&attr)), sizeof(int));
            g1_mul(*ct3i, *ct3i, s_prime[attr.get_occurrence()]);

            bn_util_scalar_product(temp, order, v, row);

            g1_mul(temp_g1, order_hash, temp);
            g1_add(*ct3i, *ct3i, temp_g1);
            ct.ct3[attr] = ct3i;
        }
        delete msp;
        bn_free(temp);
        g1_free(temp_g1);
        g1_free(order_hash);
        ct.d = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.d);
        gt_exp(*ct.d, *pk.eg1g2_alpha, *v[0]);
        for (int i = 0; i < cols; ++i) {
            bn_free(*v[i]);
            free(v[i]);
        }
        gt_mul(*ct.d, message, *ct.d);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const std::optional<MSPMatrix *> msp_opt = MSPMatrix::from_TTree_decrypt(ct.policy, sk.identity, order);
        if (!msp_opt.has_value()) {
            std::cerr << "FABEO CPABE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        MSPMatrix *msp = msp_opt.value();
        std::map<MSPAttribute, bn_t *> omegas = solve_msp(order, msp);

        g1_t prod_sks[ct.tau];
        g1_t prod_ct, temp_g1;
        for (int i = 0; i < ct.tau; ++i) {
            g1_util_null_init(prod_sks[i]);
            g1_set_infty(prod_sks[i]);
        }
        g1_util_null_init(prod_ct);
        g1_util_null_init(temp_g1);
        g1_set_infty(prod_ct);
        std::vector<std::set<int>> j_sets;
        for (int i = 0; i < msp->get_rows(); ++i) {
            MSPAttribute msp_attr = msp->get_attr_from_row(i);
            const int attr = msp_attr.get_attribute();
            const int occ = msp_attr.get_occurrence();
            g1_mul(temp_g1, *sk.sk2.at(attr), *omegas.at(msp_attr));
            g1_add(prod_sks[occ], prod_sks[occ], temp_g1);
            g1_mul(temp_g1, *ct.ct3.at(msp_attr), *omegas.at(msp_attr));
            g1_add(prod_ct, prod_ct, temp_g1);
        }
        g1_free(temp_g1);
        for (const auto& [k, v] : omegas) {
            bn_free(*v);
            free(v);
        }
        delete msp;
        gt_t temp_gt;
        gt_util_null_init(temp_gt);
        pc_map(message, *sk.sk1, *ct.ct1);
        for (int i = 0; i < ct.tau; ++i) {
            pc_map(temp_gt, prod_sks[i], *ct.ct2.at(i));
            gt_mul(message, message, temp_gt);
        }
        pc_map(temp_gt, prod_ct, *sk.sk3);
        gt_util_div(message, temp_gt, message);
        gt_free(temp_gt);
        gt_mul(message, *ct.d, message);
    }

    void free_master_key(const master_key& mk) {
        bn_free(*mk.alpha);
        free(mk.alpha);
    }

    void free_public_key(const public_key& pk) {
        gt_free(*pk.eg1g2_alpha);
        free(pk.eg1g2_alpha);
    }

    void free_secret_key(secret_key& sk) {
        sk.identity.clear();
        g1_free(*sk.sk1);
        free(sk.sk1);
        for (const auto& [k, v] : sk.sk2) {
            g1_free(*v);
            free(v);
        }
        sk.sk2.clear();
        g2_free(*sk.sk3);
        free(sk.sk3);
    }

    void free_ciphertext(ciphertext& ct) {
        delete ct.policy;
        g2_free(*ct.ct1);
        free(ct.ct1);
        for (const auto val : ct.ct2) {
            g2_free(*val);
            free(val);
        }
        ct.ct2.clear();
        for (const auto& [k, v] : ct.ct3) {
            g1_free(*v);
            free(v);
        }
        ct.ct3.clear();
        gt_free(*ct.d);
        free(ct.d);
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk) {
        serialize_bn_t(data, *mk.alpha);
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr) {
        master_key mk{};
        mk.alpha = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.alpha);
        deserialize_bn_t(*mk.alpha, data, offset_ptr);
        return mk;
    }

    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk) {
        serialize_gt_t(data, *pk.eg1g2_alpha);
    }

    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr) {
        public_key pk{};
        pk.eg1g2_alpha = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.eg1g2_alpha);
        deserialize_gt_t(*pk.eg1g2_alpha, data, offset_ptr);
        return pk;
    }
}