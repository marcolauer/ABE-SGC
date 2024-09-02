#include "fabeo_kpabe.h"
#include <vector>
#include <map>
#include <set>
#include <iostream>
#include "../MSPMatrix.h"
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace fabeo_kpabe {
    void setup(master_key& mk, public_key& pk, bn_t order) {
        mk.alpha = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.alpha);
        bn_rand_mod(*mk.alpha, order);
        pk.eg1g2_alpha = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.eg1g2_alpha);
        gt_exp_gen(*pk.eg1g2_alpha, *mk.alpha);
    }

    void key_generation(secret_key& sk, bn_t order, TTree *policy, const master_key& mk) {
        sk.policy = policy->clone();
        sk.tau = policy->get_max_occurrence() + 1;
        MSPMatrix *msp = MSPMatrix::from_TTree(policy, order);
        const size_t rows = msp->get_rows();
        const size_t cols = msp->get_cols();
        if (cols < 1) {
            std::cerr << "FABEO KPABE: Empty MSPMatrix" << std::endl;
            exit(-1);
        }

        bn_t r_prime[sk.tau];
        sk.sk1.reserve(sk.tau);
        for (int i = 0; i < sk.tau; ++i) {
            bn_util_null_init(r_prime[i]);
            bn_rand_mod(r_prime[i], order);
            auto sk1i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*sk1i)
            g2_mul_gen(*sk1i, r_prime[i]);
            sk.sk1.push_back(sk1i);
        }
        std::vector<bn_t *> v(cols);
        v[0] = mk.alpha;
        for (int i = 1; i < cols; ++i) {
            v[i] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*v[i]);
            bn_rand_mod(*v[i], order);
        }
        bn_t temp;
        g1_t temp_g1;
        bn_util_null_init(temp);
        g1_util_null_init(temp_g1);
        for (int i = 0; i < rows; ++i) {
            MSPAttribute attr = msp->get_attr_from_row(i);
            std::vector<bn_t *> row = msp->get_row(i);
            bn_util_scalar_product(temp, order, v, row);
            auto sk2attr = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*sk2attr);
            g1_mul_gen(*sk2attr, temp);
            g1_map(temp_g1, static_cast<const uint8_t *>(static_cast<void *>(&attr)), sizeof(int));
            g1_mul(temp_g1, temp_g1, r_prime[attr.get_occurrence()]);
            g1_add(*sk2attr, *sk2attr, temp_g1);
            sk.sk2[attr] = sk2attr;
        }
        delete msp;
        for (int i = 0; i < sk.tau; ++i) {
            bn_free(r_prime[i]);
        }
        for (int i = 1; i < cols; ++i) {
            bn_free(*v[i])
            free(v[i]);
        }
        bn_free(temp);
        g1_free(temp_g1);
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk) {
        ct.identity = identity;
        bn_t s;
        bn_util_null_init(s);
        bn_rand_mod(s, order);
        for (const auto attr : identity) {
            auto ct1attr = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*ct1attr);
            g1_map(*ct1attr, static_cast<const uint8_t *>(static_cast<void *>(const_cast<int *>(&attr))), sizeof(int));
            g1_mul(*ct1attr, *ct1attr, s);
            ct.ct1[attr] = ct1attr;
        }
        ct.ct2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.ct2);
        g2_mul_gen(*ct.ct2, s);
        ct.d = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.d);
        gt_exp(*ct.d, *pk.eg1g2_alpha, s);
        bn_free(s);
        gt_mul(*ct.d, message, *ct.d);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const std::optional<MSPMatrix *> msp_opt = MSPMatrix::from_TTree_decrypt(sk.policy, ct.identity, order);
        if (!msp_opt.has_value()) {
            std::cerr << "FABEO KPABE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        MSPMatrix *msp = msp_opt.value();
        std::map<MSPAttribute, bn_t *> omegas = solve_msp(order, msp);

        g1_t prod_sk, temp_g1;
        g1_t prod_cts[sk.tau];
        for (int i = 0; i < sk.tau; ++i) {
            g1_util_null_init(prod_cts[i]);
            g1_set_infty(prod_cts[i]);
        }
        g1_util_null_init(prod_sk);
        g1_util_null_init(temp_g1);
        g1_set_infty(prod_sk);
        std::vector<std::set<int>> j_sets;
        for (int i = 0; i < msp->get_rows(); ++i) {
            MSPAttribute msp_attr = msp->get_attr_from_row(i);
            const int attr = msp_attr.get_attribute();
            const int occ = msp_attr.get_occurrence();
            g1_mul(temp_g1, *sk.sk2.at(msp_attr), *omegas.at(msp_attr));
            g1_add(prod_sk, prod_sk, temp_g1);
            g1_mul(temp_g1, *ct.ct1.at(attr), *omegas.at(msp_attr));
            g1_add(prod_cts[occ], prod_cts[occ], temp_g1);
        }
        g1_free(temp_g1);
        for (const auto& [k, v] : omegas) {
            bn_free(*v);
            free(v);
        }
        delete msp;
        gt_t temp_gt;
        gt_util_null_init(temp_gt);
        gt_set_unity(message);
        for (int i = 0; i < sk.tau; ++i) {
            pc_map(temp_gt, prod_cts[i], *sk.sk1.at(i));
            gt_mul(message, message, temp_gt);
        }
        pc_map(temp_gt, prod_sk, *ct.ct2);
        gt_util_div(message, message, temp_gt);
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
        delete sk.policy;
        for (const auto& val : sk.sk1) {
            g2_free(*val);
            free(val);
        }
        sk.sk1.clear();
        for (const auto& [k, v] : sk.sk2) {
            g1_free(*v);
            free(v);
        }
        sk.sk2.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.identity.clear();
        for (const auto& [k, v] : ct.ct1) {
            g1_free(*v);
            free(v);
        }
        ct.ct1.clear();
        g2_free(*ct.ct2);
        free(ct.ct2);
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