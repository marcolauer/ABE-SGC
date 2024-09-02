#include "kpabe.h"
#include <vector>
#include <map>
#include <iostream>
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace kpabe {
    void setup(master_key& mk, public_key& pk, bn_t order, const int universe_size) {
        // Generate the master key mk
        mk.ts.reserve(universe_size);
        for (int i = 0; i < universe_size; ++i) {
            auto *ti = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*ti);
            bn_rand_mod(*ti, order);
            mk.ts.push_back(ti);
        }
        mk.y = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.y);
        bn_rand_mod(*mk.y, order);

        // Generate public parameters pp
        pk.Ts.reserve(universe_size);
        for (const auto ti : mk.ts) {
            auto Ti = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Ti);
            g2_mul_gen(*Ti, *ti);
            pk.Ts.push_back(Ti);
        }
        pk.Y = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.Y);
        gt_exp_gen(*pk.Y, *mk.y);
    }


    void key_generation(secret_key& sk, bn_t order, TTree *policy, const master_key& mk) {
        sk.policy = policy->clone();
        const std::map<TAttribute, bn_t *> shares = generate_polynomial_shares_ttree(order, *mk.y, policy);
        for (const auto& [tattr, exponent] : shares) {
            int attr = tattr.get_attribute();
            bn_util_div_mod(*exponent, *exponent, *mk.ts.at(attr-1), order);
            auto Di = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Di);
            g1_mul_gen(*Di, *exponent);
            bn_free(*exponent);
            free(exponent);
            sk.Ds[tattr] = Di;
        }
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& identity, const public_key& pk) {
        ct.identity = identity;
        bn_t s;
        bn_util_null_init(s);
        bn_rand_mod(s, order);
        auto Eprime = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*Eprime);
        gt_exp(*Eprime, *pk.Y, s);
        gt_mul(*Eprime, message, *Eprime);
        ct.Eprime = Eprime;
        for (const auto i : identity) {
            auto Ei = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Ei);
            g2_mul(*Ei, *pk.Ts.at(i-1), s);
            ct.Es[i] = Ei;
        }
        bn_free(s);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const auto matching_tuple = find_matching_attributes_ttree(sk.policy, ct.identity);
        if (!get<0>(matching_tuple)) {
            std::cerr << "KPABE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        const std::vector<TAttribute> policy_attributes = get<1>(matching_tuple);
        const std::set<TTree *> used_nodes = get<2>(matching_tuple);
        std::map<TAttribute, bn_t *> coeffs = generate_coefficients_ttree(order, sk.policy, used_nodes);

        const int num_attributes = policy_attributes.size();

        gt_t pairing_array[num_attributes];
        bn_t coeff_array[num_attributes];
        int count = 0;
        for (int i = 0; i < num_attributes; ++i) {
            const TAttribute& tattr = policy_attributes.at(i);
            bn_t *coeff = coeffs.at(tattr);
            int attr = tattr.get_attribute();
            if (!bn_is_zero(*coeff)) {
                gt_util_null_init(pairing_array[count]);
                bn_util_null_init(coeff_array[count]);
                pc_map(pairing_array[count], *sk.Ds.at(tattr), *ct.Es.at(attr));
                bn_copy(coeff_array[count], *coeff);
                ++count;
            }
            bn_free(*coeff);
            free(coeff);
        }
        gt_util_exp_sim_lot(message, pairing_array, coeff_array, count);
        for (int i = 0; i < count; ++i) {
            gt_free(pairing_array[i]);
            bn_free(coeff_array[i]);
        }
        gt_util_div(message, *ct.Eprime, message);
    }

    void free_master_key(master_key& mk) {
        for (const auto ti : mk.ts) {
            bn_free(*ti);
            free(ti);
        }
        mk.ts.clear();
        bn_free(*mk.y);
        free(mk.y);
    }

    void free_public_key(public_key& pk) {
        for (const auto Ti : pk.Ts) {
            g2_free(*Ti);
            free(Ti);
        }
        pk.Ts.clear();
        gt_free(*pk.Y);
        free(pk.Y);
    }

    void free_secret_key(secret_key& sk) {
        delete sk.policy;
        for (const auto& [k, v] : sk.Ds) {
            g1_free(*v);
            free(v);
        }
        sk.Ds.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.identity.clear();
        gt_free(*ct.Eprime);
        free(ct.Eprime);
        for (const auto& [k, v] : ct.Es) {
            g2_free(*v);
            free(v);
        }
        ct.Es.clear();
    }
}