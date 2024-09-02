#include "fibe_s.h"
#include <vector>
#include <map>
#include <iostream>
#include "../util.h"
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace fibe_s {
    void setup(master_key& mk, public_key& pk, bn_t order, const int universe_size) {
        // Generate the master key mk
        mk.ts.reserve(universe_size);
        for (int i = 0; i < universe_size; ++i) {
            auto ti = static_cast<bn_t *>(malloc(sizeof(bn_t)));
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
            auto Ti = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Ti);
            g1_mul_gen(*Ti, *ti);
            pk.Ts.push_back(Ti);
        }
        pk.Y = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.Y);
        gt_exp_gen(*pk.Y, *mk.y);
    }

    void key_generation(secret_key& sk, bn_t order, const int d, const std::vector<int>& identity, const master_key& mk) {
        sk.d = d;
        sk.identity = identity;
        bn_t polynomial_coefficients[d];
        bn_util_null_init(polynomial_coefficients[0]);
        bn_copy(polynomial_coefficients[0], *mk.y);
        for (int i = 1; i < d; ++i) {
            bn_util_null_init(polynomial_coefficients[i]);
            bn_rand_mod(polynomial_coefficients[i], order);
        }

        bn_t id, exponent;
        bn_util_null_init(id);
        bn_util_null_init(exponent);
        for (const auto i : identity) {
            bn_set_dig(id, i);
            bn_evl(exponent, polynomial_coefficients, id, order, d);
            auto Di = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Di);
            bn_util_div_mod(exponent, exponent, *mk.ts.at(i - 1), order);
            g2_mul_gen(*Di, exponent);
            sk.Ds[i] = Di;
        }
        bn_free(id);
        bn_free(exponent);
        for (int j = 0; j < d; ++j) {
            bn_free(*polynomial_coefficients[j]);
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
            auto Ei = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Ei);
            g1_mul(*Ei, *pk.Ts.at(i-1), s);
            ct.Es[i] = Ei;
        }
        bn_free(s);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        std::vector<int> S = vector_intersection<int>(sk.identity, ct.identity);
        if (S.size() < sk.d) {
            std::cerr << "FUZZY-IBE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        S.resize(sk.d);
        const std::vector<bn_t *> coeffs = lagrange_coefficients0(order, S);

        gt_t pairing_array[sk.d];
        bn_t coeff_array[sk.d];
        int count = 0;
        for (int i = 0; i < sk.d; ++i) {
            bn_t *coeff = coeffs.at(i);
            if (!bn_is_zero(*coeff)) {
                int attr = S.at(i);
                gt_util_null_init(pairing_array[count]);
                bn_util_null_init(coeff_array[count]);
                pc_map(pairing_array[count], *ct.Es.at(attr), *sk.Ds.at(attr));
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
            g1_free(*Ti);
            free(Ti);
        }
        pk.Ts.clear();
        gt_free(*pk.Y);
        free(pk.Y);
    }

    void free_secret_key(secret_key& sk) {
        sk.identity.clear();
        for (const auto& [k, v] : sk.Ds) {
            g2_free(*v);
            free(v);
        }
        sk.Ds.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.identity.clear();
        gt_free(*ct.Eprime);
        free(ct.Eprime);
        for (const auto& [k, v] : ct.Es) {
            g1_free(*v);
            free(v);
        }
        ct.Es.clear();
    }
}