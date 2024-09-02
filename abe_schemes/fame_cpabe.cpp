#include "fame_cpabe.h"
#include <vector>
#include <map>
#include <iostream>
#include "../MSPMatrix.h"
#include "../secret_sharing.h"
#include "../relic_util.h"
extern "C" {
#include <relic.h>
}

namespace fame_cpabe {
    void setup(master_key& mk, public_key& pk, bn_t order, const int assump_size) {
        pk.assump_size = assump_size;
        bn_t d, d_last;
        bn_util_null_init(d);
        bn_util_null_init(d_last);
        bn_rand_mod(d_last, order);

        mk.as.reserve(assump_size);
        mk.bs.reserve(assump_size);
        pk.Hs.reserve(assump_size);
        mk.g_ds.reserve(assump_size + 1);
        pk.Ts.reserve(assump_size);
        for (int i = 0; i < assump_size; ++i) {
            auto a = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*a);
            bn_rand_mod(*a, order);
            mk.as.push_back(a);
            auto H = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*H);
            g2_mul_gen(*H, *a);
            pk.Hs.push_back(H);
            bn_rand_mod(d, order);
            auto g_d = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*g_d);
            g1_mul_gen(*g_d, d);
            mk.g_ds.push_back(g_d);
            bn_util_mul_mod(d, d, *a, order);
            bn_util_add_mod(d, d, d_last, order);
            auto T = static_cast<gt_t *>(malloc(sizeof(gt_t)));
            gt_util_null_init(*T);
            gt_exp_gen(*T, d);
            pk.Ts.push_back(T);
            auto b = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*b);
            bn_rand_mod(*b, order);
            mk.bs.push_back(b);
        }
        auto g_d_last = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*g_d_last);
        g1_mul_gen(*g_d_last, d_last);
        mk.g_ds.push_back(g_d_last);
        bn_free(d);
        bn_free(d_last);
    }

    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const public_key& pk,
                        const master_key& mk) {
        sk.identity = identity;
        sk.assump_size = pk.assump_size;
        bn_t brs[pk.assump_size + 1];
        bn_util_null_init(brs[pk.assump_size]);
        bn_zero(brs[pk.assump_size]);
        sk.sk0.reserve(pk.assump_size + 1);
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_util_null_init(brs[i]);
            bn_rand_mod(brs[i], order);
            bn_util_add_mod(brs[pk.assump_size], brs[pk.assump_size], brs[i], order);
            bn_util_mul_mod(brs[i], *mk.bs.at(i), brs[i], order);
            auto h_br = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*h_br);
            g2_mul_gen(*h_br, brs[i]);
            sk.sk0.push_back(h_br);
        }
        auto h_rsum = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*h_rsum);
        g2_mul_gen(*h_rsum, brs[pk.assump_size]);
        sk.sk0.push_back(h_rsum);

        bn_t temp, sigma;
        bn_t as[pk.assump_size];
        bn_t a_invs[pk.assump_size];
        bn_util_null_init(temp);
        bn_util_null_init(sigma);
        g1_t temp_g1;
        g1_util_null_init(temp_g1);
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_util_null_init(as[i]);
            bn_copy(as[i], *mk.as.at(i));
            bn_util_null_init(a_invs[i]);
        }
        bn_mod_inv_sim(a_invs, as, order, pk.assump_size);
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_free(as[i]);
        }
        for (const auto attr : identity) {
            sk.sk[attr].reserve(pk.assump_size + 1);
            bn_rand_mod(sigma, order);
            for (int i = 0; i < pk.assump_size; ++i) {
                auto sum = static_cast<g1_t *>(malloc(sizeof(g1_t)));
                g1_util_null_init(*sum);
                g1_set_infty(*sum);
                for (int j = 0; j < pk.assump_size + 1; ++j) {
                    bn_util_mul_mod(temp, brs[j], a_invs[i], order);
                    int hash_input[3];
                    hash_input[0] = attr;
                    hash_input[1] = j + 1;
                    hash_input[2] = i + 1;
                    g1_map(temp_g1, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 3 * sizeof(int));
                    g1_mul(temp_g1, temp_g1, temp);
                    g1_add(*sum, *sum, temp_g1);
                }
                bn_util_mul_mod(temp, sigma, a_invs[i], order);
                g1_mul_gen(temp_g1, temp);
                g1_add(*sum, *sum, temp_g1);
                sk.sk[attr].push_back(sum);
            }
            auto last = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*last);
            bn_util_neg_mod(sigma, sigma, order);
            g1_mul_gen(*last, sigma);
            sk.sk[attr].push_back(last);
        }
        sk.skprimes.reserve(pk.assump_size + 1);
        bn_rand_mod(sigma, order);
        for (int i = 0; i < pk.assump_size; ++i) {
            auto sum = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*sum);
            g1_copy(*sum, *mk.g_ds[i]);
            for (int j = 0; j < pk.assump_size + 1; ++j) {
                bn_util_mul_mod(temp, brs[j], a_invs[i], order);
                int hash_input[4];
                hash_input[0] = 0;
                hash_input[1] = 1;
                hash_input[2] = j + 1;
                hash_input[3] = i + 1;
                g1_map(temp_g1, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 4 * sizeof(int));
                g1_mul(temp_g1, temp_g1, temp);
                g1_add(*sum, *sum, temp_g1);
            }
            bn_util_mul_mod(temp, sigma, a_invs[i], order);
            g1_mul_gen(temp_g1, temp);
            g1_add(*sum, *sum, temp_g1);
            sk.skprimes.push_back(sum);
        }
        auto last = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*last);
        bn_util_neg_mod(sigma, sigma, order);
        g1_mul_gen(*last, sigma);
        g1_add(*last, *mk.g_ds.at(pk.assump_size), *last);
        sk.skprimes.push_back(last);
        bn_free(temp);
        bn_free(sigma);
        for (int i = 0; i < pk.assump_size + 1; ++i) {
            bn_free(brs[i]);
        }
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_free(a_invs[i]);
        }
        g1_free(temp_g1);
    }


    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk) {
        ct.policy = policy->clone();

        MSPMatrix *msp = MSPMatrix::from_TTree(policy, order);
        const size_t rows = msp->get_rows();
        const size_t cols = msp->get_cols();
        if (cols < 1) {
            std::cerr << "FAME CPABE: Empty MSPMatrix" << std::endl;
            exit(-1);
        }

        bn_t s[pk.assump_size];
        bn_t ssum;
        bn_util_null_init(ssum);
        bn_zero(ssum);
        ct.ct0.reserve(pk.assump_size + 1);
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_util_null_init(s[i]);
            bn_rand_mod(s[i], order);
            bn_util_add_mod(ssum, ssum, s[i], order);
            auto H_s = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*H_s);
            g2_mul(*H_s, *pk.Hs.at(i), s[i]);
            ct.ct0.push_back(H_s);
        }
        auto h_ssum = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*h_ssum);
        g2_mul_gen(*h_ssum, ssum);
        ct.ct0.push_back(h_ssum);
        bn_free(ssum);

        g1_t hash_table[cols][pk.assump_size + 1][pk.assump_size];
        for (int i = 0; i < cols; ++i) {
            int hash_input[4];
            hash_input[0] = 0;
            hash_input[1] = i + 1;
            for (int j = 0; j < pk.assump_size + 1; ++j) {
                hash_input[2] = j + 1;
                for (int k = 0; k < pk.assump_size; ++k) {
                    hash_input[3] = k + 1;
                    g1_util_null_init(hash_table[i][j][k]);
                    g1_map(hash_table[i][j][k], static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 4 * sizeof(int));
                }
            }
        }
        g1_t temp_g1, sum1;
        g1_util_null_init(temp_g1);
        g1_util_null_init(sum1);
        for (int i = 0; i < rows; ++i) {
            int attr = msp->get_attr_from_row(i).get_attribute();
            std::vector<bn_t *> row = msp->get_row(i);
            ct.ct[attr].reserve(pk.assump_size + 1);
            for (int j = 0; j < pk.assump_size + 1; ++j) {
                auto sum = static_cast<g1_t *>(malloc(sizeof(g1_t)));
                g1_util_null_init(*sum);
                g1_set_infty(*sum);
                for (int k = 0; k < pk.assump_size; ++k) {
                    int hash_input[3];
                    hash_input[0] = attr;
                    hash_input[1] = j + 1;
                    hash_input[2] = k + 1;
                    g1_map(sum1, static_cast<const uint8_t *>(static_cast<void *>(&hash_input)), 3 * sizeof(int));
                    for (int l = 0; l < cols; ++l) {
                        g1_mul(temp_g1, hash_table[l][j][k], *row[l]);
                        g1_add(sum1, sum1, temp_g1);
                    }
                    g1_mul(sum1, sum1, s[k]);
                    g1_add(*sum, *sum, sum1);
                }
                ct.ct[attr].push_back(sum);
            }
        }
        delete msp;
        g1_free(temp_g1);
        g1_free(sum1);

        gt_t temp_gt;
        gt_util_null_init(temp_gt);
        auto ctprime = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ctprime);
        gt_copy(*ctprime, message);
        for (int i = 0; i < pk.assump_size; ++i) {
            gt_exp(temp_gt, *pk.Ts.at(i), s[i]);
            gt_mul(*ctprime, *ctprime, temp_gt);
        }
        for (int i = 0; i < pk.assump_size; ++i) {
            bn_free(s[i]);
        }
        gt_free(temp_gt);
        ct.ctprime = ctprime;
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const std::optional<MSPMatrix *> msp_opt = MSPMatrix::from_TTree_decrypt(ct.policy, sk.identity, order);
        if (!msp_opt.has_value()) {
            std::cerr << "FAME CPABE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        MSPMatrix *msp = msp_opt.value();
        std::map<MSPAttribute, bn_t *> omegas = solve_msp(order, msp);

        gt_t prod1_gt, prod2_gt;
        g1_t prod_H, prod_G, temp_g1;
        gt_util_null_init(prod1_gt);
        gt_util_null_init(prod2_gt);
        g1_util_null_init(prod_H);
        g1_util_null_init(prod_G);
        g1_util_null_init(temp_g1);
        gt_set_unity(prod1_gt);
        gt_set_unity(prod2_gt);
        for (int i = 0; i < sk.assump_size + 1; ++i) {
            g1_set_infty(prod_H);
            g1_set_infty(prod_G);
            for (int j = 0; j < msp->get_rows(); ++j) {
                MSPAttribute msp_attr = msp->get_attr_from_row(j);
                int attr = msp_attr.get_attribute();
                g1_mul(temp_g1, *sk.sk.at(attr).at(i), *omegas.at(msp_attr));
                g1_add(prod_H, prod_H, temp_g1);
                g1_mul(temp_g1, *ct.ct.at(attr).at(i), *omegas.at(msp_attr));
                g1_add(prod_G, prod_G, temp_g1);
            }
            g1_add(temp_g1, *sk.skprimes.at(i), prod_H);
            pc_map(message, temp_g1, *ct.ct0.at(i));
            gt_mul(prod1_gt, prod1_gt, message);
            pc_map(message, prod_G, *sk.sk0.at(i));
            gt_mul(prod2_gt, prod2_gt, message);
        }

        for (const auto& [k, v] : omegas) {
            bn_free(*v);
            free(v);
        }
        delete msp;
        g1_free(prod_H);
        g1_free(prod_G);
        gt_util_div(message, prod2_gt, prod1_gt);
        gt_free(prod1_gt);
        gt_free(prod2_gt);
        gt_mul(message, *ct.ctprime, message);
    }

    void free_master_key(master_key& mk) {
        for (const auto a : mk.as) {
            bn_free(*a);
            free(a);
        }
        mk.as.clear();
        for (const auto b : mk.bs) {
            bn_free(*b);
            free(b);
        }
        mk.bs.clear();
        for (const auto g_d : mk.g_ds) {
            g1_free(*g_d);
            free(g_d);
        }
        mk.g_ds.clear();
    }

    void free_public_key(public_key& pk) {
        for (const auto H : pk.Hs) {
            g2_free(*H);
            free(H);
        }
        pk.Hs.clear();
        for (const auto T : pk.Ts) {
            gt_free(*T);
            free(T);
        }
        pk.Ts.clear();
    }

    void free_secret_key(secret_key& sk) {
        sk.identity.clear();
        for (const auto val : sk.sk0) {
            g2_free(*val);
            free(val);
        }
        sk.sk0.clear();
        for (const auto& [k, v] : sk.sk) {
            for (const auto val : v) {
                g1_free(*val);
                free(val);
            }
        }
        sk.sk.clear();
        for (const auto val : sk.skprimes) {
            g1_free(*val);
            free(val);
        }
        sk.skprimes.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        delete ct.policy;
        for (const auto val : ct.ct0) {
            g2_free(*val);
            free(val);
        }
        ct.ct0.clear();
        for (const auto& [k, v] : ct.ct) {
            for (const auto val : v) {
                g1_free(*val);
                free(val);
            }
        }
        ct.ct.clear();
        gt_free(*ct.ctprime);
        free(ct.ctprime);
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk) {
        serialize_bn_t_vector<uint8_t>(data, mk.as);
        serialize_bn_t_vector<uint8_t>(data, mk.bs);
        serialize_g1_t_vector<uint8_t>(data, mk.g_ds);
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr) {
        master_key mk;
        mk.as = deserialize_bn_t_vector<uint8_t>(data, offset_ptr);
        mk.bs = deserialize_bn_t_vector<uint8_t>(data, offset_ptr);
        mk.g_ds = deserialize_g1_t_vector<uint8_t>(data, offset_ptr);
        return mk;
    }

    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk) {
        serialize_int<uint8_t>(data, pk.assump_size);
        serialize_g2_t_vector<uint8_t>(data, pk.Hs);
        serialize_gt_t_vector<uint8_t>(data, pk.Ts);
    }

    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr) {
        public_key pk;
        pk.assump_size = deserialize_int<uint8_t>(data, offset_ptr);
        pk.Hs = deserialize_g2_t_vector<uint8_t>(data, offset_ptr);
        pk.Ts = deserialize_gt_t_vector<uint8_t>(data, offset_ptr);
        return pk;
    }
}