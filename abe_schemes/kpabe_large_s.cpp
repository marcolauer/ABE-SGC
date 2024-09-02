#include "kpabe_large_s.h"
#include <vector>
#include <map>
#include <numeric>
#include <iostream>
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace kpabe_large_s {
    void setup(master_key& mk, public_key& pk, bn_t order, const int n) {
        // Generate the master key mk
        mk.y = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.y);
        bn_rand_mod(*mk.y, order);

        // Generate public parameters pp
        pk.n = n;
        pk.g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.g1);
        g1_rand(*pk.g1);
        pk.g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.g2);
        g2_mul_gen(*pk.g2, *mk.y);
        pk.ts.reserve(n+1);
        for (int i = 0; i < n+1; ++i) {
            auto ti = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*ti);
            g1_rand(*ti);
            pk.ts.push_back(ti);
        }
    }

    void key_generation(secret_key& sk, bn_t order, TTree *policy, const public_key& pk, const master_key& mk) {
        sk.policy = policy->clone();
        // For lagrange interpolation
        const int npp = pk.n + 1;
        std::vector<int> S(npp);
        iota(S.begin(), S.end(), 1);
        // Choose Polynomial
        const std::map<TAttribute, bn_t *> shares = generate_polynomial_shares_ttree(order, *mk.y, policy);
        // Element initialization
        bn_t id, temp;
        bn_util_null_init(id);
        bn_util_null_init(temp);
        g1_t temp_g1;
        g1_util_null_init(temp_g1);

        g1_t g1_pre[RLC_EP_TABLE_MAX];
        g1_mul_pre(g1_pre, *pk.g1);

        for (const auto& [tattr, q] : shares) {
            bn_set_dig(id, tattr.get_attribute());
            auto Di = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Di);
            // T(attr)
            bn_mxp_dig(temp, id, pk.n, order);
            g1_mul_fix(*Di, g1_pre, temp);
            std::vector<bn_t *> coeffs = lagrange_coefficients(order, id, S);
            for (int i = 0; i < npp; ++i) {
                g1_mul(temp_g1, *pk.ts.at(i), *coeffs.at(i));
                g1_add(*Di, *Di, temp_g1);
            }
            for (const auto val : coeffs) {
                bn_free(*val);
                free(val);
            }
            // T(attr)^r_i
            bn_rand_mod(temp, order);
            g1_mul(*Di, *Di, temp);
            // Rs
            auto Ri = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Ri);
            g2_mul_gen(*Ri, temp);
            sk.Rs[tattr] = Ri;
            // g1^q(attr)
            g1_mul_fix(temp_g1, g1_pre, *q);
            g1_add(*Di, temp_g1, *Di);
            sk.Ds[tattr] = Di;
            bn_free(*q);
            free(q);
        }
        for (int i = 0; i < RLC_EP_TABLE_MAX; ++i) {
            g1_free(g1_pre[i]);
        }
        bn_free(id);
        bn_free(temp);
        g1_free(temp_g1);
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk) {
        ct.identity = identity;
        bn_t s;
        bn_util_null_init(s);
        bn_rand_mod(s, order);

        auto Eprime = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*Eprime);
        pc_map(*Eprime, *pk.g1, *pk.g2);
        gt_exp(*Eprime, *Eprime, s);
        gt_mul(*Eprime, message, *Eprime);
        ct.Eprime = Eprime;

        auto Eprimeprime = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*Eprimeprime);
        g2_mul_gen(*Eprimeprime, s);
        ct.Eprimeprime = Eprimeprime;

        const int npp = pk.n + 1;
        bn_t id, temp;
        bn_util_null_init(id);
        bn_util_null_init(temp);
        g1_t temp_g1;
        g1_util_null_init(temp_g1);

        g1_t g1_pre[RLC_EP_TABLE_MAX];
        g1_mul_pre(g1_pre, *pk.g1);

        std::vector<int> S(npp);
        iota(S.begin(), S.end(), 1);

        for (const auto attr : identity) {
            bn_set_dig(id, attr);
            std::vector<bn_t *> coeffs = lagrange_coefficients(order, id, S);
            auto Ei = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Ei);
            bn_mxp_dig(temp, id, pk.n, order);
            g1_mul_fix(*Ei, g1_pre, temp);
            for (int i = 0; i < npp; ++i) {
                g1_mul(temp_g1, *pk.ts.at(i), *coeffs.at(i));
                g1_add(*Ei, *Ei, temp_g1);
            }
            for (const auto val : coeffs) {
                bn_free(*val);
                free(val);
            }
            g1_mul(*Ei, *Ei, s);
            ct.Es[attr] = Ei;
        }
        for (int i = 0; i < RLC_EP_TABLE_MAX; ++i) {
            g1_free(g1_pre[i]);
        }
        bn_free(s);
        bn_free(id);
        bn_free(temp);
        g1_free(temp_g1);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const auto matching_tuple = find_matching_attributes_ttree(sk.policy, ct.identity);
        if (!get<0>(matching_tuple)) {
            std::cerr << "KPABE LARGE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        const std::vector<TAttribute> policy_attributes = get<1>(matching_tuple);
        const std::set<TTree *> used_nodes = get<2>(matching_tuple);
        std::map<TAttribute, bn_t *> coeffs = generate_coefficients_ttree(order, sk.policy, used_nodes);

        const int num_attributes = policy_attributes.size();

        gt_t pairing_array[num_attributes];
        bn_t coeff_array[num_attributes];
        int count = 0;
        gt_t temp;
        gt_util_null_init(temp);
        for (int i = 0; i < num_attributes; ++i) {
            const TAttribute& tattr = policy_attributes.at(i);
            bn_t *coeff = coeffs.at(tattr);
            int attr = tattr.get_attribute();
            if (!bn_is_zero(*coeff)) {
                gt_util_null_init(pairing_array[count]);
                bn_util_null_init(coeff_array[count]);
                pc_map(pairing_array[count], *ct.Es.at(attr), *sk.Rs.at(tattr));
                pc_map(temp, *sk.Ds.at(tattr), *ct.Eprimeprime);
                gt_util_div(pairing_array[count], pairing_array[count], temp);
                bn_copy(coeff_array[count], *coeff);
                ++count;
            }
            bn_free(*coeff);
            free(coeff);
        }
        gt_free(temp);
        gt_util_exp_sim_lot(message, pairing_array, coeff_array, count);
        for (int i = 0; i < count; ++i) {
            gt_free(pairing_array[i]);
            bn_free(coeff_array[i]);
        }
        gt_mul(message, message, *ct.Eprime);
    }

    void free_master_key(const master_key& mk) {
        bn_free(*mk.y);
        free(mk.y);
    }

    void free_public_key(public_key& pk) {
        g1_free(*pk.g1);
        free(pk.g1);
        g1_free(*pk.g2);
        free(pk.g2);
        for (const auto ti : pk.ts) {
            g1_free(*ti);
            free(ti);
        }
        pk.ts.clear();
    }

    void free_secret_key(secret_key& sk) {
        delete sk.policy;
        for (const auto& [k, v] : sk.Ds) {
            g1_free(*v);
            free(v);
        }
        sk.Ds.clear();
        for (const auto& [k, v] : sk.Rs) {
            g2_free(*v);
            free(v);
        }
        sk.Rs.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.identity.clear();
        gt_free(*ct.Eprime);
        free(ct.Eprime);
        g2_free(*ct.Eprimeprime);
        free(ct.Eprimeprime);
        for (const auto& [k, v] : ct.Es) {
            g1_free(*v);
            free(v);
        }
        ct.Es.clear();
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk) {
        serialize_bn_t(data, *mk.y);
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr) {
        master_key mk;
        mk.y = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.y);
        deserialize_bn_t(*mk.y, data, offset_ptr);
        return mk;
    }
}