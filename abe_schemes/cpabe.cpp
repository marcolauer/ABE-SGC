#include "cpabe.h"

#include <chrono>
#include <vector>
#include "../secret_sharing.h"
#include "../relic_util.h"
#include "../serialize.h"

namespace cpabe {
    void setup(master_key& mk, public_key& pk, bn_t order) {
        // Exponents
        bn_t alpha;
        bn_util_null_init(alpha);
        bn_rand_mod(alpha, order);
        auto beta = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*beta);
        bn_rand_mod(*beta, order);

        // Public Parameter h
        pk.h = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.h);
        g2_mul_gen(*pk.h, *beta);
        // Master Key
        mk.g_alpha = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*mk.g_alpha);
        g1_mul_gen(*mk.g_alpha, alpha);
        bn_mod_inv(*beta, *beta, order);
        mk.beta_inv = beta;
        // Public parameters (rest)
        pk.egg_alpha = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.egg_alpha);
        gt_exp_gen(*pk.egg_alpha, alpha);
        bn_free(alpha);
    }

    void key_generation(secret_key& sk, bn_t order, const std::vector<int>& identity, const master_key& mk) {
        sk.identity = identity;
        bn_t r, rj;
        bn_util_null_init(r);
        bn_util_null_init(rj);
        g1_t grG1;
        g1_util_null_init(grG1);
        g2_t grG2;
        g2_util_null_init(grG2);
        bn_rand_mod(r, order);
        g1_mul_gen(grG1, r);
        g2_mul_gen(grG2, r);

        sk.D = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        g1_util_null_init(*sk.D);
        g1_add(*sk.D, grG1, *mk.g_alpha);
        g1_mul(*sk.D, *sk.D, *mk.beta_inv);
        for (const auto attr : identity) {
            bn_rand_mod(rj, order);
            auto Di = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Di);
            g2_map(*Di, static_cast<const uint8_t *>(static_cast<void *>(const_cast<int *>(&attr))), sizeof(int));
            g2_mul(*Di, *Di, rj);
            g2_add(*Di, grG2, *Di);
            sk.Ds[attr] = Di;
            auto Dprimei = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Dprimei);
            g1_mul_gen(*Dprimei, rj);
            sk.Dprimes[attr] = Dprimei;
        }
        bn_free(r);
        bn_free(rj);
        g1_free(grG1);
        g1_free(grG2);
    }

    void encryption(ciphertext& ct, bn_t order, gt_t message, TTree *policy, const public_key& pk) {
        ct.policy = policy->clone();
        bn_t s;
        bn_util_null_init(s);
        bn_rand_mod(s, order);

        const std::map<TAttribute, bn_t *> shares = generate_polynomial_shares_ttree(order, s, policy);

        // C_circum
        ct.C_circum = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*ct.C_circum);
        gt_exp(*ct.C_circum, *pk.egg_alpha, s);
        gt_mul(*ct.C_circum, message, *ct.C_circum);
        // C
        ct.C = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*ct.C);
        g2_mul(*ct.C, *pk.h, s);

        for (const auto& [tattr, exponent] : shares) {
            int attr = tattr.get_attribute();
            auto Ci = static_cast<g1_t *>(malloc(sizeof(g1_t)));
            g1_util_null_init(*Ci);
            g1_mul_gen(*Ci, *exponent);
            ct.Cs[tattr] = Ci;
            auto Cprimei = static_cast<g2_t *>(malloc(sizeof(g2_t)));
            g2_util_null_init(*Cprimei);
            g2_map(*Cprimei, static_cast<const uint8_t *>(static_cast<void *>(&attr)), sizeof(int));
            g2_mul(*Cprimei, *Cprimei, *exponent);
            ct.Cprimes[tattr] = Cprimei;
            bn_free(*exponent);
            free(exponent);
        }
        bn_free(s);
    }

    void decryption(gt_t message, bn_t order, const ciphertext& ct, const secret_key& sk) {
        const auto matching_tuple = find_matching_attributes_ttree(ct.policy, sk.identity);
        if (!get<0>(matching_tuple)) {
            std::cerr << "CPABE: Attributes for Decryption do not match" << std::endl;
            exit(-1);
        }
        const std::vector<TAttribute> policy_attributes = get<1>(matching_tuple);
        const std::set<TTree *> used_nodes = get<2>(matching_tuple);
        std::map<TAttribute, bn_t *> coeffs = generate_coefficients_ttree(order, ct.policy, used_nodes);

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
                pc_map(pairing_array[count], *ct.Cs.at(tattr), *sk.Ds.at(attr));
                pc_map(temp, *sk.Dprimes.at(attr), *ct.Cprimes.at(tattr));
                gt_util_div(pairing_array[count], pairing_array[count], temp);
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
        gt_mul(message, message, *ct.C_circum);
        pc_map(temp, *sk.D, *ct.C);
        gt_util_div(message, message, temp);
        gt_free(temp);
    }

    void free_master_key(const master_key& mk) {
        bn_free(*mk.beta_inv);
        free(mk.beta_inv);
        g1_free(*mk.g_alpha);
        free(mk.g_alpha);
    }

    void free_public_key(const public_key& pk) {
        g2_free(*pk.h);
        free(pk.h);
        gt_free(*pk.egg_alpha);
        free(pk.egg_alpha);
    }

    void free_secret_key(secret_key& sk) {
        sk.identity.clear();
        g1_free(*sk.D);
        free(sk.D);
        for (const auto& [k, v] : sk.Ds) {
            g2_free(*v);
            free(v);
        }
        sk.Ds.clear();
        for (const auto& [k, v] : sk.Dprimes) {
            g1_free(*v);
            free(v);
        }
        sk.Dprimes.clear();
    }

    void free_ciphertext(ciphertext& ct) {
        delete ct.policy;
        gt_free(*ct.C_circum);
        free(ct.C_circum);
        g2_free(*ct.C);
        free(ct.C);
        for (const auto& [k, v] : ct.Cs) {
            g1_free(*v);
            free(v);
        }
        ct.Cs.clear();
        for (const auto& [k, v] : ct.Cprimes) {
            g2_free(*v);
            free(v);
        }
        ct.Cprimes.clear();
    }

    void serialize_mk(std::vector<unsigned char>& data, const master_key& mk) {
        serialize_bn_t(data, *mk.beta_inv);
        serialize_g1_t(data, *mk.g_alpha);
    }

    master_key deserialize_mk(const std::vector<unsigned char>& data, int *offset_ptr) {
        master_key mk;
        mk.beta_inv = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*mk.beta_inv);
        deserialize_bn_t(*mk.beta_inv, data, offset_ptr);
        mk.g_alpha = static_cast<g1_t *>(malloc(sizeof(g1_t)));
        gt_util_null_init(*mk.g_alpha);
        deserialize_g1_t(*mk.g_alpha, data, offset_ptr);
        return mk;
    }

    void serialize_pk(std::vector<unsigned char>& data, const public_key& pk) {
        serialize_g2_t(data, *pk.h);
        serialize_gt_t(data, *pk.egg_alpha);
    }

    public_key deserialize_pk(const std::vector<unsigned char>& data, int *offset_ptr) {
        public_key pk;
        pk.h = static_cast<g2_t *>(malloc(sizeof(g2_t)));
        g2_util_null_init(*pk.h);
        deserialize_g2_t(*pk.h, data, offset_ptr);
        pk.egg_alpha = static_cast<gt_t *>(malloc(sizeof(gt_t)));
        gt_util_null_init(*pk.egg_alpha);
        deserialize_gt_t(*pk.egg_alpha, data, offset_ptr);
        return pk;
    }
}