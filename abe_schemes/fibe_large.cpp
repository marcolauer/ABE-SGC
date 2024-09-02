#include "fibe_large.h"
#include <vector>
#include <map>
#include <numeric>
#include <iostream>
#include "../util.h"
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace fibe_large {
    void setup(master_key& mk, public_key& pk, bn_t order, const int n) {
        // Generate the master key mk
        mk.y = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.y);
        bn_rand_mod(*mk.y, order);

        // Generate public parameters pp
        pk.n = n;
        pk.g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.g1);
        g1_mul_gen(*pk.g1, *mk.y);
        pk.g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.g2);
        g2_rand(*pk.g2);
        pk.ts.reserve(n+1);
        for (int i = 0; i < n+1; ++i) {
            auto ti = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*ti);
            g2_rand(*ti);
            pk.ts.push_back(ti);
        }
    }

    void key_generation(secret_key& sk, bn_t order, const int d, const std::vector<int>& identity, const public_key& pk,
                        const master_key& mk) {
        sk.d = d;
        sk.identity = identity;
        // For lagrange interpolation
        const int npp = pk.n + 1;
        std::vector<int> S(npp);
        iota(S.begin(), S.end(), 1);
        // Choose Polynomial
        bn_t polynomial_coefficients[d];
        bn_util_null_init(polynomial_coefficients[0]);
        bn_copy(polynomial_coefficients[0], *mk.y);
        for (int j = 1; j < d; ++j) {
            bn_util_null_init(polynomial_coefficients[j]);
            bn_rand_mod(polynomial_coefficients[j], order);
        }

        bn_t id, temp;
        bn_util_null_init(id);
        bn_util_null_init(temp);
        g2_t temp_g2;
        g2_util_null_init(temp_g2);

        g2_t g2_pre[RLC_EP_TABLE_MAX];
        g2_mul_pre(g2_pre, *pk.g2);

        for (const auto attr : identity) {
            bn_set_dig(id, attr);
            auto Di = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Di);
            // T(attr)
            bn_mxp_dig(temp, id, pk.n, order);
            g2_mul_fix(*Di, g2_pre, temp);
            std::vector<bn_t *> coeffs = lagrange_coefficients(order, id, S);
            for (int i = 0; i < npp; ++i) {
                g2_mul(temp_g2, *pk.ts.at(i), *coeffs.at(i));
                g2_add(*Di, *Di, temp_g2);
            }
            for (const auto val : coeffs) {
                bn_free(*val);
                free(val);
            }
            // T(attr)^r_i
            bn_rand_mod(temp, order);
            g2_mul(*Di, *Di, temp);
            // ds
            auto di = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*di);
            g1_mul_gen(*di, temp);
            sk.ds[attr] = di;
            // g2^q(attr)
            bn_evl(temp, polynomial_coefficients, id, order, d);
            g2_mul_fix(temp_g2, g2_pre, temp);
            g2_add(*Di, temp_g2, *Di);
            sk.Ds[attr] = Di;
        }
        for (int j = 0; j < d; ++j) {
            bn_free(polynomial_coefficients[j]);
        }
        for (int i = 0; i < RLC_EP_TABLE_MAX; ++i) {
            g2_free(g2_pre[i]);
        }
        bn_free(id);
        bn_free(temp);
        g2_free(temp_g2);
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

        auto Eprimeprime = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*Eprimeprime);
        g1_mul_gen(*Eprimeprime, s);
        ct.Eprimeprime = Eprimeprime;

        const int npp = pk.n + 1;
        bn_t id, temp;
        bn_util_null_init(id);
        bn_util_null_init(temp);
        g2_t temp_g2;
        g2_util_null_init(temp_g2);

        g2_t g2_pre[RLC_EP_TABLE_MAX];
        g2_mul_pre(g2_pre, *pk.g2);

        std::vector<int> S(npp);
        iota(S.begin(), S.end(), 1);

        for (const auto attr : identity) {
            bn_set_dig(id, attr);
            std::vector<bn_t *> coeffs = lagrange_coefficients(order, id, S);
            auto Ei = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Ei);
            bn_mxp_dig(temp, id, pk.n, order);
            g2_mul_fix(*Ei, g2_pre, temp);
            for (int i = 0; i < npp; ++i) {
                g2_mul(temp_g2, *pk.ts.at(i), *coeffs.at(i));
                g2_add(*Ei, *Ei, temp_g2);
            }
            for (const auto val : coeffs) {
                bn_free(*val);
                free(val);
            }
            g2_mul(*Ei, *Ei, s);
            ct.Es[attr] = Ei;
        }
        for (int i = 0; i < RLC_EP_TABLE_MAX; ++i) {
            g2_free(g2_pre[i]);
        }
        bn_free(s);
        bn_free(id);
        bn_free(temp);
        g2_free(temp_g2);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        std::vector<int> S = vector_intersection<int>(sk.identity, ct.identity);
        if (S.size() < sk.d) {
            std::cerr << "FUZZY-IBE LARGE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        S.resize(sk.d);
        const std::vector<bn_t *> coeffs = lagrange_coefficients0(order, S);

        gt_t pairing_array[sk.d];
        bn_t coeff_array[sk.d];
        int count = 0;
        gt_t temp;
        gt_util_null_init(temp);
        for (int i = 0; i < sk.d; ++i) {
            bn_t *coeff = coeffs.at(i);
            if (!bn_is_zero(*coeff)) {
                int attr = S.at(i);
                gt_util_null_init(pairing_array[count]);
                bn_util_null_init(coeff_array[count]);
                pc_map(pairing_array[count], *sk.ds.at(attr), *ct.Es.at(attr));
                pc_map(temp, *ct.Eprimeprime, *sk.Ds.at(attr));
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
        g2_free(*pk.g1);
        free(pk.g1);
        g2_free(*pk.g2);
        free(pk.g2);
        for (const auto ti : pk.ts) {
            g2_free(*ti);
            free(ti);
        }
        pk.ts.clear();
    }

    void free_secret_key(secret_key& sk) {
        sk.identity.clear();
        for (const auto& [k, v] : sk.Ds) {
            g2_free(*v);
            free(v);
        }
        sk.Ds.clear();
        for (const auto& [k, v] : sk.ds) {
            g1_free(*v);
            free(v);
        }
        sk.ds.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.identity.clear();
        gt_free(*ct.Eprime);
        free(ct.Eprime);
        g1_free(*ct.Eprimeprime);
        free(ct.Eprimeprime);
        for (const auto& [k, v] : ct.Es) {
            g2_free(*v);
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