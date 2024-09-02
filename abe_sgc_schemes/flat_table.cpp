#include "flat_table.h"
#include <bitset>
#include <chrono>
#include <cmath>
#include <iostream>
#include <set>
#include <cstring>
#include <iomanip>

#include "../abe_schemes/cpabe_switcher.h"
#include "../relic_util.h"
#include "../random.h"
#include "../crypto_functions/aes.h"
#include "../serialize.h"
#include "../config.h"

#if MASTER_DEVICE == MASTER_PC
#include "minbool.h"
#include "../bfm/espresso.h"
#endif

using namespace cpabe_switcher;

// Cheung et al. - Collusion-Resistant Group Key Management Using Attribute-Based Encryption - 2007

// Adjustments:
// - Instead of sending multiple messages on member leave events, we send one encrypted with an OR node as the root of the policy
// - Periodic refresh: send K' and the conversion factor encrypted in one message

// Limits Parameters:
// - ID length
const int n = MASTER_FT_ID_LENGTH;
// - ids < 2^16
#if MASTER_FT_ID_LENGTH > 8
using ID_TYPE = uint16_t;
#else
using ID_TYPE = uint8_t;
#endif

// Make sure that:
// - sizeof(ID_TYPE)*8 >= n
// - 16*sizeof(ID_TYPE) < uint8_t.MAX

// Length of the used symmetric keys
constexpr int byte_length = 16;

struct flat_table_gc_state {
    master_key mk;
    public_key pk;
    std::vector<unsigned char> group_key;
    std::set<ID_TYPE> current_ids;
};

struct flat_table_gm_state {
    ID_TYPE id{};
    secret_key sk;
    std::vector<unsigned char> individual_key{}; // Shared only with GC
    std::vector<unsigned char> group_key{};
};

struct flat_table_join_message {
    std::vector<unsigned char> old_member_message{};
    std::vector<unsigned char> new_member_message{};
};

std::string bfm_type_to_string(const bfm_type bfm_type) {
    switch(bfm_type) {
        case QUINE_MC_CLUSKEY:
            return "Quine-McCluskey";
        case ESPRESSO:
            return "Espresso";
    }
    return "";
}

std::vector<uint8_t> flat_table_id_to_attrs(ID_TYPE id) {
    std::vector<uint8_t> result;
    for (int i = 0; i < n; ++i) {
        if (id & 1) {
            result.push_back(2 * (i + 1));
        } else {
            result.push_back(2 * i + 1);
        }
        id >>= 1;
    }
    return result;
}

std::vector<ID_TYPE> flat_table_get_dc_values(const std::set<ID_TYPE>& important_values) {
    auto it = important_values.begin();
    std::vector<ID_TYPE> result;
    for (int i = 0; i < std::pow(2, n); ++i) {
        if (i == *it && it != important_values.end()) {
            ++it;
        } else {
            result.push_back(i);
        }
    }
    return result;
}

#if MASTER_DEVICE == MASTER_PC
// Returns minimal SOPE (sum of products expression)
TTree *flat_table_quine_mccluskey(const std::set<ID_TYPE>& current_ids) {
    std::vector<ID_TYPE> dc_vec;
    const std::vector on_vec(current_ids.begin(), current_ids.end());
    const std::vector<minbool::MinTerm<n>> solution = minbool::minimize_boolean<n>(on_vec, dc_vec);

    std::map<int, int> attribute_occurances;
    std::vector<TTree *> subtrees;
    for (const auto& term : solution) {
        std::vector<TTree *> attributes;
        for (uint8_t i = 0; i < n; ++i) {
            const auto val = term[i];
            if (val == minbool::MinTerm<n>::Zero) {
                int attr = 2 * i + 1;
                attributes.push_back(new TAttribute(attr, attribute_occurances[attr]++));
            } else if (val == minbool::MinTerm<n>::One) {
                int attr = 2 * (i + 1);
                attributes.push_back(new TAttribute(attr, attribute_occurances[attr]++));
            }
        }
        const int num_attrs = attributes.size();
        if (num_attrs == 1) {
            subtrees.push_back(attributes.at(0));
        } else {
            subtrees.push_back(new TThreshold(num_attrs, num_attrs, attributes));
        }
    }
    TTree *policy = new TThreshold(1, solution.size(), subtrees);
    return policy;
}

// Returns an approximation of the minimal SOPE (sum of products expression)
TTree *flat_table_espresso(const std::set<ID_TYPE>& current_ids) {
    std::set important(current_ids.begin(), current_ids.end());
    std::vector<ID_TYPE> dc_vec;
    const std::vector on_vec(current_ids.begin(), current_ids.end());
    const std::vector<std::string> solution = espresso<n>(on_vec, dc_vec);

    std::map<int, int> attribute_occurances;
    std::vector<TTree *> subtrees;
    for (const auto& term : solution) {
        std::vector<TTree *> attributes;
        for (int i = 0; i < n; ++i) {
            const auto val = term[i];
            if (val == '0') {
                int attr = 2 * i + 1;
                attributes.push_back(new TAttribute(attr, attribute_occurances[attr]++));
            } else if (val == '1') {
                int attr = 2 * (i + 1);
                attributes.push_back(new TAttribute(attr, attribute_occurances[attr]++));
            }
        }
        const int num_attrs = attributes.size();
        if (num_attrs == 1) {
            subtrees.push_back(attributes.at(0));
        } else {
            subtrees.push_back(new TThreshold(num_attrs, num_attrs, attributes));
        }
    }
    TTree *policy = new TThreshold(1, solution.size(), subtrees);
    return policy;
}
#endif

void flat_table_setup(flat_table_gc_state& gc_state, std::map<ID_TYPE, flat_table_gm_state>& gm_states, bn_t order,
                  const int num_users, const abe_type cpabe_type) {
    setup(gc_state.mk, gc_state.pk, order, cpabe_type);
    gc_state.group_key = byte_vector_random(byte_length);
    for (int i = 0; i < num_users; ++i) {
        gc_state.current_ids.insert(i);
        flat_table_gm_state& gm_state = gm_states[i];
        gm_state.id = i;
        gm_state.sk = init_secret_key(cpabe_type);
        const std::vector<uint8_t> identity = flat_table_id_to_attrs(gm_state.id);
        key_generation(gm_state.sk, order, std::vector<int>(identity.begin(), identity.end()),
                       gc_state.pk, gc_state.mk, cpabe_type);
        gm_state.group_key = std::vector(gc_state.group_key);
    }
}

std::vector<unsigned char> flat_table_refresh_gc(flat_table_gc_state& gc_state, bn_t order, const abe_type cpabe_type) {
    if (cpabe_type != CPABE) {
        std::cerr << "Refresh Function is only defined for CPABE" << std::endl;
        exit(-1);
    }
    auto& mk = std::get<cpabe::master_key>(gc_state.mk);
    auto& pk = std::get<cpabe::public_key>(gc_state.pk);
    bn_t alpha_new;
    bn_util_null_init(alpha_new);
    bn_rand_mod(alpha_new, order);
    auto g_alpha_new = static_cast<g1_t *>(malloc(sizeof(g1_t)));
    g1_util_null_init(*g_alpha_new);
    g1_mul_gen(*g_alpha_new, alpha_new);
    gt_exp_gen(*pk.egg_alpha, alpha_new);
    g1_t conversion_factor;
    g1_util_null_init(conversion_factor);
    g1_sub(conversion_factor, *g_alpha_new, *mk.g_alpha);
    g1_mul(conversion_factor, conversion_factor, *mk.beta_inv);
    free(mk.g_alpha);
    mk.g_alpha = g_alpha_new;
    bn_free(alpha_new);
    std::vector plaintext = byte_vector_random(byte_length);
    serialize_g1_t(plaintext, conversion_factor);
    g1_free(conversion_factor);
    std::vector<unsigned char> message = aes_encrypt(gc_state.group_key, plaintext);
    gc_state.group_key = std::vector(plaintext.begin(), plaintext.begin() + byte_length);
    message.insert(message.begin(), 'r');
    return message;
}

void flat_table_refresh_gm(flat_table_gm_state& gm_state, const std::vector<unsigned char>& message, const abe_type cpabe_type) {
    if (cpabe_type != CPABE) {
        std::cerr << "Refresh Function is only defined for CPABE" << std::endl;
        exit(-1);
    }
    auto& sk = std::get<cpabe::secret_key>(gm_state.sk);
    std::vector<unsigned char> plaintext = aes_decrypt(gm_state.individual_key, message.data() + 1, message.size() - 1);
    gm_state.group_key = std::vector(plaintext.begin(), plaintext.begin() + byte_length);
    g1_t conversion_factor;
    g1_util_null_init(conversion_factor);
    int offset = byte_length;
    deserialize_g1_t(conversion_factor, plaintext, &offset);
    g1_add(*sk.D, *sk.D, conversion_factor);
    g1_free(conversion_factor);
}

flat_table_join_message flat_table_join_gc(flat_table_gc_state& gc_state, bn_t order, const ID_TYPE id,
                                   const std::vector<unsigned char>& individual_key, const abe_type cpabe_type){
    gc_state.current_ids.insert(id);
    // Old GMs
    flat_table_join_message message;
    std::vector<unsigned char> data = byte_vector_random(byte_length);
    message.old_member_message = aes_encrypt(gc_state.group_key, data);
    message.old_member_message.insert(message.old_member_message.begin(), 'j');
    // New GM
    const std::vector<uint8_t> identity = flat_table_id_to_attrs(id);
    serialize_int<ID_TYPE>(data, id);
    secret_key sk = init_secret_key(cpabe_type);
    key_generation(sk, order, std::vector<int>(identity.begin(), identity.end()), gc_state.pk,
                   gc_state.mk, cpabe_type);
    serialize_sk<uint8_t, uint8_t>(data, sk, cpabe_type);
    free_secret_key(sk, cpabe_type);
    message.new_member_message = aes_encrypt(individual_key, data);
    message.new_member_message.insert(message.new_member_message.begin(), 'J');
    // Update Group Key
    gc_state.group_key = std::vector(data.begin(), data.begin() + byte_length);
    return message;
}

void flat_table_join_gm_new(flat_table_gm_state& gm_state, const std::vector<unsigned char>& message, const abe_type cpabe_type) {
    std::vector<unsigned char> plaintext = aes_decrypt(gm_state.individual_key, message.data() + 1, message.size() - 1);
    gm_state.group_key = std::vector(plaintext.begin(), plaintext.begin() + byte_length);
    int offset = byte_length;
    gm_state.id = deserialize_int<ID_TYPE>(plaintext, &offset);
    gm_state.sk = deserialize_sk<uint8_t, uint8_t>(plaintext, &offset, cpabe_type);
}

void flat_table_join_gm_old(flat_table_gm_state& gm_state, const std::vector<unsigned char>& message) {
    gm_state.group_key = aes_decrypt(gm_state.group_key, message.data() + 1, message.size() - 1);
}

std::vector<unsigned char> flat_table_leave_gc(flat_table_gc_state& gc_state, bn_t order, const ID_TYPE id,
                                           const bfm_type bfm_type, const abe_type cpabe_type) {
    gc_state.current_ids.erase(id);

    TTree *policy;
#if MASTER_DEVICE == MASTER_ESP32
    std::cerr << "ESP32 cannot run BFM functions" << std::endl;
    exit(-1);
#elif MASTER_DEVICE == MASTER_PC
    switch (bfm_type) {
        case QUINE_MC_CLUSKEY:
            policy = flat_table_quine_mccluskey(gc_state.current_ids);
            break;
        case ESPRESSO:
            policy = flat_table_espresso(gc_state.current_ids);
            break;
    }
#endif

    gt_t m;
    gt_util_null_init(m);
    gt_rand(m);
    gc_state.group_key = gt_util_to_aes_key(m, byte_length);
    ciphertext ct = init_ciphertext(cpabe_type);
    encryption(ct, order, m, policy, gc_state.pk, cpabe_type);
    delete policy;
    gt_free(m);

    std::vector<unsigned char> message{'l'};
    serialize_ct<uint8_t, uint8_t>(message, ct, cpabe_type);
    free_ciphertext(ct, cpabe_type);
    return message;
}

void flat_table_leave_gm(flat_table_gm_state& gm_state, bn_t order, const std::vector<unsigned char>& message,
                     const abe_type cpabe_type) {
    int offset = 1;
    ciphertext ct = deserialize_ct<uint8_t, uint8_t>(message, &offset, cpabe_type);
    gt_t m;
    gt_util_null_init(m);
    decryption(m, order, ct, gm_state.sk, cpabe_type);
    free_ciphertext(ct, cpabe_type);
    gm_state.group_key = gt_util_to_aes_key(m, byte_length);
    gt_free(m);
}

void flat_table_update_gm(flat_table_gm_state& gm_state, bn_t order, const std::vector<unsigned char>& message,
                      const abe_type cpabe_type) {
    const unsigned char action = message.at(0);
    if (action == 'r') {
        flat_table_refresh_gm(gm_state, message, cpabe_type);
    } else if (action == 'j') {
        flat_table_join_gm_old(gm_state, message);
    } else if (action == 'J') {
        flat_table_join_gm_new(gm_state, message, cpabe_type);
    } else {
        flat_table_leave_gm(gm_state, order, message, cpabe_type);
    }
}

void flat_table_test(int size, const bfm_type bfm_type, const abe_type cpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(cpabe_type);
    const std::string minimizer_string = bfm_type_to_string(bfm_type);

    const int join_user = size;
    constexpr int leave_user = 0;
    flat_table_gc_state gc_state{init_master_key(cpabe_type), init_public_key(cpabe_type)};
    std::map<ID_TYPE, flat_table_gm_state> gm_states;

    flat_table_setup(gc_state, gm_states, order, size, cpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    const flat_table_join_message join_message = flat_table_join_gc(gc_state, order, join_user, join_ind_key, cpabe_type);
    for (auto& [id, gm_state] : gm_states) {
        flat_table_update_gm(gm_state, order, join_message.old_member_message, cpabe_type);
    }
    gm_states[join_user].individual_key = join_ind_key;
    flat_table_update_gm(gm_states.at(join_user), order, join_message.new_member_message, cpabe_type);

    const std::vector<unsigned char> leave_message = flat_table_leave_gc(gc_state, order, leave_user, bfm_type, cpabe_type);
    free_secret_key(gm_states.at(leave_user).sk, cpabe_type);
    gm_states.erase(leave_user);
    for (auto& [id, gm_state] : gm_states) {
        flat_table_update_gm(gm_state, order, leave_message, cpabe_type);
    }

    const std::vector<unsigned char>& gc_group_key = gc_state.group_key;
    for (const auto& [user, state] : gm_states) {
        if (std::memcmp(gc_group_key.data(), state.group_key.data(), byte_length) != 0) {
            std::cerr << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << "): The communication key of user " << user << " does not match the server communication key" << std::endl;
            exit(-1);
        }
    }
    std::cout << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << "): The server communication key matches all user communication keys" << std::endl;

    // Cleanup
    free_master_key(gc_state.mk, cpabe_type);
    free_public_key(gc_state.pk, cpabe_type);
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, cpabe_type);
    }
    bn_free(order);
}

void flat_table_run_gc(const int size, const int precision, const int repetitions, const bfm_type bfm_type,
                   const abe_type cpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(cpabe_type);
    const std::string minimizer_string = bfm_type_to_string(bfm_type);

    const int join_user = size;
    const int leave_user = size - 1;
    flat_table_gc_state gc_state{init_master_key(cpabe_type), init_public_key(cpabe_type)};
    std::map<ID_TYPE, flat_table_gm_state> gm_states;

    flat_table_setup(gc_state, gm_states, order, size, cpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    long join_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        auto begin = std::chrono::steady_clock::now();
        flat_table_join_gc(gc_state, order, join_user, join_ind_key, cpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.erase(join_user);
    }
    auto [mean, stddev] = calculate_mean_stddev(join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") GC Join Time: Avg: " << mean/1000 << " \\pm " << stddev/1000 << std::endl;

    long leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        auto begin = std::chrono::steady_clock::now();
        flat_table_leave_gc(gc_state, order, leave_user, bfm_type, cpabe_type);
        auto end = std::chrono::steady_clock::now();
        leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.insert(leave_user);
    }
    auto [mean2, stddev2] = calculate_mean_stddev(leave_times, repetitions);
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") GC Leave Time: Avg: " << mean2/1000 << " \\pm " << stddev2/1000 << std::endl;

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, cpabe_type);
    }
    free_master_key(gc_state.mk, cpabe_type);
    free_public_key(gc_state.pk, cpabe_type);
    bn_free(order);
}

void flat_table_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                              const int size, const int repetitions, const bfm_type bfm_type, const abe_type cpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    int message_counter = 0;
    const std::string abe_type_string = type_to_string(cpabe_type);

    const int join_user_new = size;
    const int join_user_old = size - 1;
    const int leave_user = size - 2;
    flat_table_gc_state gc_state{init_master_key(cpabe_type), init_public_key(cpabe_type)};
    std::map<ID_TYPE, flat_table_gm_state> gm_states;

    flat_table_setup(gc_state, gm_states, order, size, cpabe_type);

    for (int i = 0; i < repetitions; ++i) {
        const flat_table_join_message join_message = flat_table_join_gc(gc_state, order, join_user_new,
                                                                            join_ind_key, cpabe_type);
        save_bytes_to_file(join_message.new_member_message, file_prefix + std::to_string(message_counter++));
        if (i != repetitions - 1) {
            gc_state.current_ids.erase(join_user_new);
        }
    }

    for (int i = 0; i < repetitions; ++i) {
        gc_state.current_ids.erase(join_user_old);
        const flat_table_join_message join_message = flat_table_join_gc(gc_state, order, join_user_old,
                                                                            join_ind_key, cpabe_type);
        save_bytes_to_file(join_message.old_member_message, file_prefix + std::to_string(message_counter++));
    }
    gc_state.current_ids.erase(join_user_old);

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> leave_message = flat_table_leave_gc(gc_state, order, leave_user, bfm_type, cpabe_type);
        save_bytes_to_file(leave_message, file_prefix + std::to_string(message_counter++));
        gc_state.current_ids.insert(leave_user);
    }

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, cpabe_type);
    }
    free_master_key(gc_state.mk, cpabe_type);
    free_public_key(gc_state.pk, cpabe_type);
    bn_free(order);
}

void flat_table_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key, const int precision,
                   const int repetitions, const bfm_type bfm_type, const abe_type cpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    int message_counter = 0;
    const std::string abe_type_string = type_to_string(cpabe_type);
    const std::string minimizer_string = bfm_type_to_string(bfm_type);

    flat_table_gm_state gm_state{};
    gm_state.individual_key = join_ind_key;

    long join_new_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(file_prefix + std::to_string(message_counter++));
        auto begin = std::chrono::steady_clock::now();
        flat_table_update_gm(gm_state, order, message, cpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_new_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        if (i != repetitions - 1) {
            free_secret_key(gm_state.sk, cpabe_type);
        }
    }
    auto [mean, stddev] = calculate_mean_stddev(join_new_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") GM New Join Time: Avg: " << mean/1000 << " \\pm " << stddev/1000 << std::endl;

    long join_old_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(file_prefix + std::to_string(message_counter++));
        auto begin = std::chrono::steady_clock::now();
        flat_table_update_gm(gm_state, order, message, cpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_old_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean2, stddev2] = calculate_mean_stddev(join_old_times, repetitions);
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") GM Old Join Time: Avg: " << mean2/1000 << " \\pm " << stddev2/1000 << std::endl;

    long leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(file_prefix + std::to_string(message_counter++));
        auto begin = std::chrono::steady_clock::now();
        flat_table_update_gm(gm_state, order, message, cpabe_type);
        auto end = std::chrono::steady_clock::now();
        leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean3, stddev3] = calculate_mean_stddev(leave_times, repetitions);
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") GM Leave Time: Avg: " << mean3/1000 << " \\pm " << stddev3/1000 << std::endl;

    // Cleanup
    free_secret_key(gm_state.sk, cpabe_type);
    bn_free(order);
}

void flat_table_measure_byte_lengths(const int size, const bfm_type bfm_type, const abe_type cpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(cpabe_type);
    const std::string minimizer_string = bfm_type_to_string(bfm_type);

    const int join_user = size + 1;
    const int leave_user = size;
    flat_table_gc_state gc_state{init_master_key(cpabe_type), init_public_key(cpabe_type)};
    std::map<ID_TYPE, flat_table_gm_state> gm_states;

    flat_table_setup(gc_state, gm_states, order, size, cpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    const flat_table_join_message join_message =  flat_table_join_gc(gc_state, order, join_user, join_ind_key, cpabe_type);
    gc_state.current_ids.erase(join_user);
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") New Join Message Size: " << join_message.new_member_message.size() << std::endl;
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") Old Join Message Size: " << join_message.old_member_message.size() << std::endl;

    const std::vector<unsigned char> leave_message = flat_table_leave_gc(gc_state, order, leave_user, bfm_type, cpabe_type);
    gc_state.current_ids.insert(leave_user);
    std::cout << "%" << "FLAT TABLE " << abe_type_string << " (" << minimizer_string << ") Leave Message Size: " << leave_message.size() << std::endl;

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, cpabe_type);
    }
    free_master_key(gc_state.mk, cpabe_type);
    free_public_key(gc_state.pk, cpabe_type);
    bn_free(order);
}