#include "cpabbe_s.h"

#include <vector>
#include <iostream>
#include <chrono>
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}


namespace cpabbe_s {
    void setup(master_key& mk, public_key& pk, bn_t order, const int n, const int N, const int N1) {
        // Generate the master key mk
        mk.alpha = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.alpha);
        bn_rand_mod(*mk.alpha, order);
        mk.gamma = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.gamma);
        bn_rand_mod(*mk.gamma, order);
        mk.delta = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.delta);
        bn_rand_mod(*mk.delta, order);
        mk.theta = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.theta);
        bn_rand_mod(*mk.theta, order);
        // Generate public key pk
        pk.n = n;
        pk.N1 = N1;
        pk.hs_g2.reserve(N);
        pk.hs_g1.reserve(N);
        bn_t temp;
        bn_util_null_init(temp);
        for (int i = 0; i < N; ++i) {
            bn_rand_mod(temp, order);
            auto *hi_g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*hi_g2);
            g2_mul_gen(*hi_g2, temp);
            pk.hs_g2.push_back(hi_g2);
            auto *hi_g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*hi_g1);
            g1_mul_gen(*hi_g1, temp);
            pk.hs_g1.push_back(hi_g1);
        }
        bn_copy(temp, *mk.alpha);
        pk.gs_g2.reserve(n);
        pk.gs_g1.reserve(n);
        for (int i = 0; i < 2*n - 1; ++i) {
            auto *gi_g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*gi_g2);
            g2_mul_gen(*gi_g2, temp);
            pk.gs_g2.push_back(gi_g2);
            auto *gi_g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*gi_g1);
            g1_mul_gen(*gi_g1, temp);
            pk.gs_g1.push_back(gi_g1);
            if (i == n - 1) {
                bn_util_mul_mod(temp, temp, *mk.alpha, order);
            } else if (i == 2*n - 2) {
                break;
            }
            bn_util_mul_mod(temp, temp, *mk.alpha, order);
        }
        bn_free(temp);
        pk.ny = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.ny);
        g1_mul_gen(*pk.ny, *mk.gamma);
        pk.v0 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.v0);
        g1_mul_gen(*pk.v0, *mk.delta);
        pk.v1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*pk.v1);
        g1_mul_gen(*pk.v1, *mk.theta);
    }


    void key_generation(secret_key& sk, bn_t order, const int id, const std::vector<int>& V, const std::vector<int>& Z,
                        const public_key& pk, const master_key& mk) {
        sk.id = id;
        sk.n = pk.n;
        for (int i = 0; i < sk.n; ++i) {
            auto gi_g2_new = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*gi_g2_new);
            g2_copy(*gi_g2_new, *pk.gs_g2[sk.id + i - 1]);
            sk.gs_g2.push_back(gi_g2_new);
        }
        const int n2 = V.size();
        const int n3 = Z.size();
        bn_t temp1, temp2;
        bn_util_null_init(temp1);
        bn_util_null_init(temp2);
        // D4
        bn_rand_mod(temp1, order);
        sk.D4s = std::vector<g2_t *>(pk.N1+1);
        g2_t v_hs[n2];
        for (int i = 0; i < n2; ++i) {
            g2_util_null_init(v_hs[i]);
            g2_copy(v_hs[i], *pk.hs_g2[V[i]-1]);
        }
        for (int i = 0; i < pk.N1+1; ++i) {
            auto D4i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*D4i);
            g2_set_infty(*D4i);
            for (int j = 0; j < n2; ++j) {
                g2_add(*D4i, *D4i, v_hs[j]);
            }
            g2_mul(*D4i, *D4i, temp1);
            sk.D4s[i] = D4i;
            if (i != pk.N1) {
                for (int j = 0; j < n2; ++j) {
                    g2_util_mul_int_mod(v_hs[j], v_hs[j], V[j], order);
                }
            }
        }
        // D2
        sk.D2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D2);
        g2_mul_gen(*sk.D2, temp1);
        bn_util_mul_mod(temp2, *mk.delta, temp1, order);
        // D5
        bn_rand_mod(temp1, order);
        sk.D5s = std::vector<g2_t *>(pk.N1+1);
        g2_t z_hs[n3];
        for (int i = 0; i < n3; ++i) {
            g2_util_null_init(z_hs[i]);
            g2_copy(z_hs[i], *pk.hs_g2[Z[i]-1]);
        }
        for (int i = 0; i < pk.N1+1; ++i) {
            auto D5i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*D5i);
            g2_set_infty(*D5i);
            for (int j = 0; j < n3; ++j) {
                g2_add(*D5i, *D5i, z_hs[j]);
            }
            g2_mul(*D5i, *D5i, temp1);
            sk.D5s[i] = D5i;
            if (i != pk.N1) {
                for (int j = 0; j < n3; ++j) {
                    g2_util_mul_int_mod(z_hs[j], z_hs[j], Z[j], order);
                }
            }
        }
        // D3
        sk.D3 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D3);
        g2_mul_gen(*sk.D3, temp1);
        // D1
        bn_util_mul_mod(temp1, *mk.theta, temp1, order);
        bn_util_add_mod(temp1, temp2, temp1, order);
        bn_util_mxp_int(temp2, *mk.alpha, id, order);
        bn_util_mul_mod(temp2, temp2, *mk.gamma, order);
        bn_util_add_mod(temp1, temp2, temp1, order);
        sk.D1 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*sk.D1);
        g2_mul_gen(*sk.D1, temp1);
        bn_free(temp1);
        bn_free(temp2);
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& S, const std::vector<int>& J,
                    const std::vector<int>& V, const std::vector<int>& Z, const public_key& pk) {
        ct.S = S;
        ct.J = J;
        const int n2 = V.size();
        const int n3 = Z.size();
        std::vector<bn_t *> as = phuong_coefficients(order, J);
        bn_t r;
        bn_util_null_init(r);
        bn_rand_mod(r, order);
        // C0
        ct.C0 = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.C0);
        pc_map(*ct.C0, *pk.gs_g1[0], *pk.gs_g2[pk.n-1]);
        gt_exp(*ct.C0, *ct.C0, r);
        gt_mul(*ct.C0, message, *ct.C0);
        // C1
        ct.C1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C1);
        g1_mul_gen(*ct.C1, r);
        // C2
        ct.C2 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C2);
        g1_copy(*ct.C2, *pk.ny);
        for (const auto j : S) {
            g1_add(*ct.C2, *ct.C2, *pk.gs_g1[pk.n-j]);
        }
        g1_mul(*ct.C2, *ct.C2, r);
        // C3
        g1_t c3_hs[n2];
        bn_t c3_exps[n2];
        for (int i = 0; i < n2; ++i) {
            g1_util_null_init(c3_hs[i]);
            g1_copy(c3_hs[i], *pk.hs_g1[V[i]-1]);
            bn_util_null_init(c3_exps[i]);
            bn_set_dig(c3_exps[i], 1);
            for (const auto wj: J) {
                bn_util_mul_int_mod(c3_exps[i], c3_exps[i], V[i] - wj, order);
            }
        }
        ct.C3 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C3);
        g1_util_mul_sim_lot(*ct.C3, c3_hs, c3_exps, n2);
        g1_add(*ct.C3, *pk.v0, *ct.C3);
        g1_mul(*ct.C3, *ct.C3, r);
        for (int i = 0; i < n2; ++i) {
            g1_free(c3_hs[i]);
            bn_free(c3_exps[i]);
        }
        // C4
        g1_t c4_hs[n3];
        bn_t c4_exps[n3];
        for (int i = 0; i < n3; ++i) {
            g1_util_null_init(c4_hs[i]);
            g1_copy(c4_hs[i], *pk.hs_g1[Z[i]-1]);
            bn_util_null_init(c4_exps[i]);
            bn_set_dig(c4_exps[i], 1);
            for (const auto wj: J) {
                bn_util_mul_int_mod(c4_exps[i], c4_exps[i], Z[i] - wj, order);
            }
        }
        ct.C4 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*ct.C4);
        g1_util_mul_sim_lot(*ct.C4, c4_hs, c4_exps, n3);
        g1_add(*ct.C4, *pk.v1, *ct.C4);
        g1_mul(*ct.C4, *ct.C4, r);
        for (int i = 0; i < n3; ++i) {
            g1_free(c4_hs[i]);
            bn_free(c4_exps[i]);
        }
        for (const auto a : as) {
            bn_free(*a);
            free(a);
        }
        bn_free(r);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        std::vector<bn_t *> as = phuong_coefficients(order, ct.J);
        // Numerator
        gt_t denominator;
        gt_util_null_init(denominator);
        g2_t g2s_num[4];
        g2_util_null_init(g2s_num[0]);
        g2_copy(g2s_num[0], *sk.D1);
        const int n1pp = ct.J.size() + 1;
        bn_t as_array[n1pp];
        g2_t D4s[n1pp];
        g2_t D5s[n1pp];
        for (int i = 0; i < n1pp; ++i) {
            bn_util_null_init(as_array[i]);
            g2_util_null_init(D4s[i]);
            g2_util_null_init(D5s[i]);
            bn_copy(as_array[i], *as[i]);
            g2_copy(D4s[i], *sk.D4s[i]);
            g2_copy(D5s[i], *sk.D5s[i]);
        }
        g2_util_null_init(g2s_num[1]);
        g2_util_mul_sim_lot(g2s_num[1], D4s, as_array, n1pp);
        g2_util_null_init(g2s_num[2]);
        g2_util_mul_sim_lot(g2s_num[2], D5s, as_array, n1pp);
        g2_util_null_init(g2s_num[3]);
        g2_set_infty(g2s_num[3]);
        for (const auto i : ct.S) {
            if (i > sk.id) {
                g2_add(g2s_num[3], g2s_num[3], *sk.gs_g2[sk.n - i + 1]);
            }
            if (i < sk.id) {
                g2_add(g2s_num[3], g2s_num[3], *sk.gs_g2[sk.n - i]);
            }
        }
        g1_t g1s_num[4];
        g1_util_null_init(g1s_num[0]);
        g1_copy(g1s_num[0], *ct.C1);
        g1_util_null_init(g1s_num[1]);
        g1_copy(g1s_num[1], *ct.C1);
        g1_util_null_init(g1s_num[2]);
        g1_copy(g1s_num[2], *ct.C1);
        g1_util_null_init(g1s_num[3]);
        g1_copy(g1s_num[3], *ct.C1);
        pc_map_sim(message, g1s_num, g2s_num, 4);
        gt_mul(message, *ct.C0, message);
        g2_free(g2s_num[0]);
        g2_free(g2s_num[1]);
        g2_free(g2s_num[2]);
        g2_free(g2s_num[3]);
        g1_free(g1s_num[0]);
        g1_free(g1s_num[1]);
        g1_free(g1s_num[2]);
        g1_free(g1s_num[3]);

        // Denominator
        g2_t g2s_den[3];
        g2_util_null_init(g2s_den[0]);
        g2_copy(g2s_den[0], *sk.gs_g2[0]);
        g2_util_null_init(g2s_den[1]);
        g2_copy(g2s_den[1], *sk.D2);
        g2_util_null_init(g2s_den[2]);
        g2_copy(g2s_den[2], *sk.D3);
        g1_t g1s_den[3];
        g1_util_null_init(g1s_den[0]);
        g1_copy(g1s_den[0], *ct.C2);
        g1_util_null_init(g1s_den[1]);
        g1_copy(g1s_den[1], *ct.C3);
        g1_util_null_init(g1s_den[2]);
        g1_copy(g1s_den[2], *ct.C4);
        pc_map_sim(denominator, g1s_den, g2s_den, 3);
        gt_util_div(message, message, denominator);
        g2_free(g2s_den[0]);
        g2_free(g2s_den[1]);
        g2_free(g2s_den[2]);
        g1_free(g1s_den[0]);
        g1_free(g1s_den[1]);
        g1_free(g1s_den[2]);
        gt_free(denominator);
        for (const auto a : as) {
            bn_free(*a);
            free(a);
        }
    }

    void free_master_key(const master_key& mk) {
        bn_free(*mk.alpha);
        free(mk.alpha);
        bn_free(*mk.gamma);
        free(mk.gamma);
        bn_free(*mk.delta);
        free(mk.delta);
        bn_free(*mk.theta);
        free(mk.theta);
    }

    void free_public_key(public_key& pk) {
        for (const auto gi : pk.gs_g2) {
            g2_free(*gi);
            free(gi);
        }
        pk.gs_g2.clear();
        for (const auto gi : pk.gs_g1) {
            g1_free(*gi);
            free(gi);
        }
        pk.gs_g1.clear();
        for (const auto hi : pk.hs_g2) {
            g2_free(*hi);
            free(hi);
        }
        pk.hs_g2.clear();
        for (const auto hi : pk.hs_g1) {
            g1_free(*hi);
            free(hi);
        }
        pk.hs_g1.clear();
        g1_free(*pk.ny);
        free(pk.ny);
        g1_free(*pk.v0);
        free(pk.v0);
        g1_free(*pk.v1);
        free(pk.v1);
    }

    void free_secret_key(secret_key& sk) {
        for (const auto gi_g2 : sk.gs_g2) {
            g2_free(*gi_g2);
            free(gi_g2);
        }
        sk.gs_g2.clear();
        g2_free(*sk.D1);
        free(sk.D1);
        g2_free(*sk.D2);
        free(sk.D2);
        g2_free(*sk.D3);
        free(sk.D3);
        for (const auto D4i : sk.D4s) {
            g2_free(*D4i);
            free(D4i);
        }
        sk.D4s.clear();
        for (const auto D5i : sk.D5s) {
            g2_free(*D5i);
            free(D5i);
        }
        sk.D5s.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        ct.S.clear();
        ct.J.clear();
        gt_free(*ct.C0);
        free(ct.C0);
        g1_free(*ct.C1);
        free(ct.C1);
        g1_free(*ct.C2);
        free(ct.C2);
        g1_free(*ct.C3);
        free(ct.C3);
        g1_free(*ct.C4);
        free(ct.C4);
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk) {
        serialize_bn_t(data, *mk.alpha);
        serialize_bn_t(data, *mk.gamma);
        serialize_bn_t(data, *mk.delta);
        serialize_bn_t(data, *mk.theta);
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr) {
        master_key mk;
        mk.alpha = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.alpha);
        deserialize_bn_t(*mk.alpha, data, offset_ptr);
        mk.gamma = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.gamma);
        deserialize_bn_t(*mk.gamma, data, offset_ptr);
        mk.delta = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.delta);
        deserialize_bn_t(*mk.delta, data, offset_ptr);
        mk.theta = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.theta);
        deserialize_bn_t(*mk.theta, data, offset_ptr);
        return mk;
    }
}
