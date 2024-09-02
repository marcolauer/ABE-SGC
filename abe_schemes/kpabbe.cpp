#include "kpabbe.h"

#include <vector>
#include <iostream>
#include <chrono>
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}


namespace kpabbe {
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
        mk.xs.reserve(N1);
        for (int i = 0; i < N1; ++i) {
            auto *xi = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*xi);
            bn_rand_mod(*xi, order);
            mk.xs.push_back(xi);
        }
        // Generate public key pk
        pk.n = n;
        pk.N1 = N1;
        pk.hs_g1.reserve(N);
        pk.hs_g2.reserve(N);
        bn_t temp;
        bn_util_null_init(temp);
        for (int i = 0; i < N; ++i) {
            bn_rand_mod(temp, order);
            auto *hi_g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*hi_g1);
            g1_mul_gen(*hi_g1, temp);
            pk.hs_g1.push_back(hi_g1);
            auto *hi_g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*hi_g2);
            g2_mul_gen(*hi_g2, temp);
            pk.hs_g2.push_back(hi_g2);
        }
        bn_copy(temp, *mk.alpha);
        pk.gs_g1.reserve(n);
        pk.gs_g2.reserve(n);
        for (int i = 0; i < 2*n - 1; ++i) {
            auto *gi_g1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*gi_g1);
            g1_mul_gen(*gi_g1, temp);
            pk.gs_g1.push_back(gi_g1);
            auto *gi_g2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*gi_g2);
            g2_mul_gen(*gi_g2, temp);
            pk.gs_g2.push_back(gi_g2);
            if (i == n - 1) {
                bn_util_mul_mod(temp, temp, *mk.alpha, order);
            } else if (i == 2*n - 2) {
                break;
            }
            bn_util_mul_mod(temp, temp, *mk.alpha, order);
        }
        bn_free(temp);
        pk.ny = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.ny);
        g2_mul_gen(*pk.ny, *mk.gamma);
        pk.v0 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.v0);
        g2_mul_gen(*pk.v0, *mk.delta);
        pk.v1 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.v1);
        g2_mul_gen(*pk.v1, *mk.theta);
        pk.v0s.reserve(N1);
        pk.v1s.reserve(N1);
        for (int i = 0; i < N1; ++i) {
            auto *v0i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*v0i);
            g2_mul(*v0i, *pk.v0, *mk.xs[i]);
            pk.v0s.push_back(v0i);
            auto *v1i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*v1i);
            g2_mul(*v1i, *pk.v1, *mk.xs[i]);
            pk.v1s.push_back(v1i);
        }
    }


    void key_generation(secret_key& sk, bn_t order, const int id, const std::vector<int>& J, const std::vector<int>& V,
                        const std::vector<int>& Z, const public_key& pk, const master_key& mk) {
        sk.id = id;
        sk.n = pk.n;
        sk.J = J;
        for (int i = 0; i < sk.n; ++i) {
            auto gi_g1_new = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*gi_g1_new);
            g1_copy(*gi_g1_new, *pk.gs_g1[sk.id + i - 1]);
            sk.gs_g1.push_back(gi_g1_new);
        }
        const int n1 = J.size();
        bn_t temp1, temp2, temp3;
        bn_util_null_init(temp1);
        bn_util_null_init(temp2);
        bn_util_null_init(temp3);
        std::vector<bn_t *> as = phuong_coefficients(order, J);
        bn_copy(temp3, *as[0]);
        for (int i = 0; i < n1; ++i) {
            bn_util_mul_mod(temp1, *mk.xs[i], *as[i+1], order);
            bn_util_add_mod(temp3, temp3, temp1, order);
        }
        // D5 ohne s2/t
        const int n3 = Z.size();
        g1_t d5_hs[n3];
        bn_t d5_exps[n3];
        for (int i = 0; i < n3; ++i) {
            g1_util_null_init(d5_hs[i]);
            g1_copy(d5_hs[i], *pk.hs_g1[Z[i]-1]);
            bn_util_null_init(d5_exps[i]);
            bn_set_dig(d5_exps[i], 1);
            for (const auto wj: J) {
                bn_util_mul_int_mod(d5_exps[i], d5_exps[i], Z[i] - wj, order);
            }
        }
        sk.D5 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D5);
        g1_util_mul_sim_lot(*sk.D5, d5_hs, d5_exps, n3);
        for (int i = 0; i < n3; ++i) {
            g1_free(d5_hs[i]);
            bn_free(d5_exps[i]);
        }
        // D4 + s1/t in temp1 speichern + delta*s1 in temp2 speichern
        const int n2 = V.size();
        g1_t d4_hs[n2];
        bn_t d4_exps[n2];
        for (int i = 0; i < n2; ++i) {
            g1_util_null_init(d4_hs[i]);
            g1_copy(d4_hs[i], *pk.hs_g1[V[i]-1]);
            bn_util_null_init(d4_exps[i]);
            bn_set_dig(d4_exps[i], 1);
            for (const auto wj: J) {
                bn_util_mul_int_mod(d4_exps[i], d4_exps[i], V[i] - wj, order);
            }
        }
        sk.D4 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D4);
        g1_util_mul_sim_lot(*sk.D4, d4_hs, d4_exps, n2);
        for (int i = 0; i < n2; ++i) {
            g1_free(d4_hs[i]);
            bn_free(d4_exps[i]);
        }
        bn_rand_mod(temp1, order);
        bn_util_mul_mod(temp2, temp1, *mk.delta, order);
        bn_util_div_mod(temp1, temp1, temp3, order);
        g1_mul(*sk.D4, *sk.D4, temp1);
        // D2
        sk.D2 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D2);
        g1_mul_gen(*sk.D2, temp1);
        // D5 rest
        bn_rand_mod(temp1, order);
        bn_util_div_mod(temp3, temp1, temp3, order);
        bn_util_mul_mod(temp1, temp1, *mk.theta, order);
        bn_util_add_mod(temp2, temp2, temp1, order);
        g1_mul(*sk.D5, *sk.D5, temp3);
        // D3
        sk.D3 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D3);
        g1_mul_gen(*sk.D3, temp3);
        // D1
        bn_util_mxp_int(temp1, *mk.alpha, id, order);
        bn_util_mul_mod(temp1, temp1, *mk.gamma, order);
        bn_util_add_mod(temp1, temp1, temp2, order);
        sk.D1 = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D1);
        g1_mul_gen(*sk.D1, temp1);

        bn_free(temp1);
        bn_free(temp2);
        bn_free(temp3);
        for (const auto a : as) {
            bn_free(*a);
            free(a);
        }
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, const std::vector<int>& S, const std::vector<int>& V,
                    const std::vector<int>& Z, const public_key& pk) {
        ct.S = S;
        const int n2 = V.size();
        const int n3 = Z.size();

        bn_t r;
        bn_util_null_init(r);
        bn_rand_mod(r, order);
        // C0
        ct.C0 = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.C0);
        pc_map(*ct.C0, *pk.gs_g1[pk.n-1], *pk.gs_g2[0]);
        gt_exp(*ct.C0, *ct.C0, r);
        gt_mul(*ct.C0, message, *ct.C0);
        // C1
        ct.C1 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.C1);
        g2_mul_gen(*ct.C1, r);
        // C2
        ct.C2 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.C2);
        g2_copy(*ct.C2, *pk.ny);
        for (const auto j : S) {
            g2_add(*ct.C2, *ct.C2, *pk.gs_g2[pk.n-j]);
        }
        g2_mul(*ct.C2, *ct.C2, r);
        // C3
        ct.C3s = std::vector<g2_t *>(pk.N1+1);
        g2_t v_hs[n2];
        for (int i = 0; i < n2; ++i) {
            g2_util_null_init(v_hs[i]);
            g2_copy(v_hs[i], *pk.hs_g2[V[i]-1]);
        }
        auto C30 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*C30);
        g2_set_infty(*C30);
        for (int i = 0; i < n2; ++i) {
            g2_add(*C30, *C30, v_hs[i]);
        }
        g2_add(*C30, *pk.v0, *C30);
        g2_mul(*C30, *C30, r);
        ct.C3s[0] = C30;
        for (int i = 0; i < pk.N1; ++i) {
            for (int j = 0; j < n2; ++j) {
                g2_util_mul_int_mod(v_hs[j], v_hs[j], V[j], order);
            }
            auto C3i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*C3i);
            g2_set_infty(*C3i);
            for (int j = 0; j < n2; ++j) {
                g2_add(*C3i, *C3i, v_hs[j]);
            }
            g2_add(*C3i, *pk.v0s[i], *C3i);
            g2_mul(*C3i, *C3i, r);
            ct.C3s[i+1] = C3i;
        }
        // C4
        ct.C4s = std::vector<g2_t *>(pk.N1+1);
        g2_t z_hs[n3];
        for (int i = 0; i < n3; ++i) {
            g2_util_null_init(z_hs[i]);
            g2_copy(z_hs[i], *pk.hs_g2[Z[i]-1]);
        }
        auto C40 = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*C40);
        g2_set_infty(*C40);
        for (int i = 0; i < n3; ++i) {
            g2_add(*C40, *C40, z_hs[i]);
        }
        g2_add(*C40, *pk.v1, *C40);
        g2_mul(*C40, *C40, r);
        ct.C4s[0] = C40;
        for (int i = 0; i < pk.N1; ++i) {
            for (int j = 0; j < n3; ++j) {
                g2_util_mul_int_mod(z_hs[j], z_hs[j], Z[j], order);
            }
            auto C4i = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*C4i);
            g2_set_infty(*C4i);
            for (int j = 0; j < n3; ++j) {
                g2_add(*C4i, *C4i, z_hs[j]);
            }
            g2_add(*C4i, *pk.v1s[i], *C4i);
            g2_mul(*C4i, *C4i, r);
            ct.C4s[i+1] = C4i;
        }
        bn_free(r);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        std::vector<bn_t *> as = phuong_coefficients(order, sk.J);
        // Numerator
        gt_t denominator;
        gt_util_null_init(denominator);
        g1_t g1s_num[4];
        g1_util_null_init(g1s_num[0]);
        g1_copy(g1s_num[0], *sk.D1);
        g1_util_null_init(g1s_num[1]);
        g1_copy(g1s_num[1], *sk.D4);
        g1_util_null_init(g1s_num[2]);
        g1_copy(g1s_num[2], *sk.D5);
        g1_util_null_init(g1s_num[3]);
        g1_set_infty(g1s_num[3]);
        for (const auto i : ct.S) {
            if (i > sk.id) {
                g1_add(g1s_num[3], g1s_num[3], *sk.gs_g1[sk.n - i + 1]);
            }
            if (i < sk.id) {
                g1_add(g1s_num[3], g1s_num[3], *sk.gs_g1[sk.n - i]);
            }
        }
        g2_t g2s_num[4];
        g2_util_null_init(g2s_num[0]);
        g2_copy(g2s_num[0], *ct.C1);
        g2_util_null_init(g2s_num[1]);
        g2_copy(g2s_num[1], *ct.C1);
        g2_util_null_init(g2s_num[2]);
        g2_copy(g2s_num[2], *ct.C1);
        g2_util_null_init(g2s_num[3]);
        g2_copy(g2s_num[3], *ct.C1);
        pc_map_sim(message, g1s_num, g2s_num, 4);
        gt_mul(message, *ct.C0, message);
        g1_free(g1s_num[0]);
        g1_free(g1s_num[1]);
        g1_free(g1s_num[2]);
        g1_free(g1s_num[3]);
        g2_free(g2s_num[0]);
        g2_free(g2s_num[1]);
        g2_free(g2s_num[2]);
        g2_free(g2s_num[3]);

        // Denominator
        g1_t g1s_den[3];
        g1_util_null_init(g1s_den[0]);
        g1_copy(g1s_den[0], *sk.gs_g1[0]);
        g1_util_null_init(g1s_den[1]);
        g1_copy(g1s_den[1], *sk.D2);
        g1_util_null_init(g1s_den[2]);
        g1_copy(g1s_den[2], *sk.D3);
        g2_t g2s_den[3];
        g2_util_null_init(g2s_den[0]);
        g2_copy(g2s_den[0], *ct.C2);
        const int n1pp = sk.J.size() + 1;
        bn_t as_array[n1pp];
        g2_t C3s[n1pp];
        g2_t C4s[n1pp];
        for (int i = 0; i < n1pp; ++i) {
            bn_util_null_init(as_array[i]);
            g2_util_null_init(C3s[i]);
            g2_util_null_init(C4s[i]);
            bn_copy(as_array[i], *as[i]);
            g2_copy(C3s[i], *ct.C3s[i]);
            g2_copy(C4s[i], *ct.C4s[i]);
        }
        g2_util_null_init(g2s_den[1]);
        g2_util_mul_sim_lot(g2s_den[1], C3s, as_array, n1pp);
        g2_util_null_init(g2s_den[2]);
        g2_util_mul_sim_lot(g2s_den[2], C4s, as_array, n1pp);
        pc_map_sim(denominator, g1s_den, g2s_den, 3);
        gt_util_div(message, message, denominator);
        g1_free(g1s_den[0]);
        g1_free(g1s_den[1]);
        g1_free(g1s_den[2]);
        g2_free(g2s_den[0]);
        g2_free(g2s_den[1]);
        g2_free(g2s_den[2]);
        gt_free(denominator);
        for (const auto a : as) {
            bn_free(*a);
            free(a);
        }
    }

    void free_master_key(master_key& mk) {
        bn_free(*mk.alpha);
        free(mk.alpha);
        bn_free(*mk.gamma);
        free(mk.gamma);
        bn_free(*mk.delta);
        free(mk.delta);
        bn_free(*mk.theta);
        free(mk.theta);
        for (const auto xi : mk.xs) {
            bn_free(*xi);
            free(xi);
        }
        mk.xs.clear();
    }

    void free_public_key(public_key& pk) {
        for (const auto gi : pk.gs_g1) {
            g1_free(*gi);
            free(gi);
        }
        pk.gs_g1.clear();
        for (const auto gi : pk.gs_g2) {
            g2_free(*gi);
            free(gi);
        }
        pk.gs_g2.clear();
        for (const auto hi : pk.hs_g1) {
            g1_free(*hi);
            free(hi);
        }
        pk.hs_g1.clear();
        for (const auto hi : pk.hs_g2) {
            g2_free(*hi);
            free(hi);
        }
        pk.hs_g2.clear();
        g2_free(*pk.ny);
        free(pk.ny);
        g2_free(*pk.v0);
        free(pk.v0);
        g2_free(*pk.v1);
        free(pk.v1);
        for (const auto v0i : pk.v0s) {
            g2_free(*v0i);
            free(v0i);
        }
        pk.v0s.clear();
        for (const auto v1i : pk.v1s) {
            g2_free(*v1i);
            free(v1i);
        }
        pk.v1s.clear();
    }

    void free_secret_key(secret_key& sk) {
        sk.J.clear();
        for (const auto gi_g1 : sk.gs_g1) {
            g1_free(*gi_g1);
            free(gi_g1);
        }
        sk.gs_g1.clear();
        g1_free(*sk.D1);
        free(sk.D1);
        g1_free(*sk.D2);
        free(sk.D2);
        g1_free(*sk.D3);
        free(sk.D3);
        g1_free(*sk.D4);
        free(sk.D4);
        g1_free(*sk.D5);
        free(sk.D5);
    }

    void free_ciphertext(ciphertext& ct) {
        ct.S.clear();
        gt_free(*ct.C0);
        free(ct.C0);
        g2_free(*ct.C1);
        free(ct.C1);
        g2_free(*ct.C2);
        free(ct.C2);
        for (const auto C3i : ct.C3s) {
            g2_free(*C3i);
            free(C3i);
        }
        ct.C3s.clear();
        for (const auto C4i : ct.C4s) {
            g2_free(*C4i);
            free(C4i);
        }
        ct.C4s.clear();
    }
}
