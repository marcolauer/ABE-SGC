#include "naive_kpabe.h"

#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <vector>
#include <cstring>
#include <iomanip>

#include "../abe_schemes/kpabe_switcher.h"
#include "../crypto_functions/aes.h"
#include "../random.h"

using namespace kpabe_switcher;

// Limits:
// - ids < 2^16
using ID_TYPE = uint16_t;

constexpr int byte_length = 16;

struct naive_kpabe_gc_state {
    master_key mk;
    public_key pk;
    std::vector<unsigned char> group_key;
    std::set<ID_TYPE> current_ids;
};

// IDs start with 1
struct naive_kpabe_gm_state {
    ID_TYPE id{};
    secret_key sk;
    std::vector<unsigned char> individual_key{}; // Shared only with GC
    std::vector<unsigned char> group_key{};
};

struct naive_kpabe_join_message {
    std::vector<unsigned char> old_member_message{};
    std::vector<unsigned char> new_member_message{};
};

void naive_kpabe_setup(naive_kpabe_gc_state& gc_state, std::map<ID_TYPE,
                              naive_kpabe_gm_state>& gm_states, bn_t order, const int num_users,
                              const abe_type kpabe_type) {
    setup(gc_state.mk, gc_state.pk, order, kpabe_type);
    gc_state.group_key = byte_vector_random(byte_length);
    for (int i = 1; i <= num_users; ++i) {
        gc_state.current_ids.insert(i);
        naive_kpabe_gm_state& gm_state = gm_states[i];
        gm_state.id = i;
        gm_state.sk = init_secret_key(kpabe_type);
        TTree *policy = new TAttribute(i);
        key_generation(gm_state.sk, order, policy, gc_state.pk, gc_state.mk, kpabe_type);
        delete policy;
        gm_state.group_key = std::vector(gc_state.group_key);
    }

}

naive_kpabe_join_message naive_kpabe_join_gc(naive_kpabe_gc_state& gc_state, bn_t order,
                                                           const ID_TYPE id,
                                                           const std::vector<unsigned char>& individual_key,
                                                           const abe_type kpabe_type) {
    gc_state.current_ids.insert(id);
    // Old GMs
    naive_kpabe_join_message message;
    std::vector<unsigned char> data = byte_vector_random(byte_length);
    message.old_member_message = aes_encrypt(gc_state.group_key, data);
    message.old_member_message.insert(message.old_member_message.begin(), 'j');
    // New GM
    TTree *policy = new TAttribute(id);
    serialize_int<ID_TYPE>(data, id);
    secret_key sk = init_secret_key(kpabe_type);
    key_generation(sk, order, policy, gc_state.pk, gc_state.mk, kpabe_type);
    delete policy;
    serialize_sk<ID_TYPE, uint8_t>(data, sk, kpabe_type);
    free_secret_key(sk, kpabe_type);
    message.new_member_message = aes_encrypt(individual_key, data);
    message.new_member_message.insert(message.new_member_message.begin(), 'J');
    // Update Group Key
    gc_state.group_key = std::vector(data.begin(), data.begin() + byte_length);
    return message;
}

void naive_kpabe_join_gm_new(naive_kpabe_gm_state& gm_state, const std::vector<unsigned char>& message,
                                    const abe_type kpabe_type) {
    std::vector<unsigned char> plaintext = aes_decrypt(gm_state.individual_key, message.data() + 1, message.size() - 1);
    gm_state.group_key = std::vector(plaintext.begin(), plaintext.begin() + byte_length);
    int offset = byte_length;
    gm_state.id = deserialize_int<ID_TYPE>(plaintext, &offset);
    gm_state.sk = deserialize_sk<ID_TYPE, uint8_t>(plaintext, &offset, kpabe_type);
}

void naive_kpabe_join_gm_old(naive_kpabe_gm_state& gm_state, const std::vector<unsigned char>& message) {
    gm_state.group_key = aes_decrypt(gm_state.group_key, message.data() + 1, message.size() - 1);
}

std::vector<unsigned char> naive_kpabe_leave_gc(naive_kpabe_gc_state& gc_state, bn_t order,
                                                       const ID_TYPE id, const abe_type kpabe_type) {
    gc_state.current_ids.erase(id);

    const auto identity = std::vector<int>{gc_state.current_ids.begin(), gc_state.current_ids.end()};
    gt_t m;
    gt_util_null_init(m);
    gt_rand(m);
    gc_state.group_key = gt_util_to_aes_key(m, byte_length);
    ciphertext ct = init_ciphertext(kpabe_type);
    encryption(ct, order, m, identity, gc_state.pk, kpabe_type);
    gt_free(m);

    std::vector<unsigned char> message{'l'};
    serialize_ct<ID_TYPE, ID_TYPE>(message, ct, kpabe_type);
    free_ciphertext(ct, kpabe_type);
    return message;
}

void naive_kpabe_leave_gm(naive_kpabe_gm_state& gm_state, bn_t order,
                                 const std::vector<unsigned char>& message, const abe_type kpabe_type) {
    int offset = 1;
    ciphertext ct = deserialize_ct<ID_TYPE, ID_TYPE>(message, &offset, kpabe_type);
    gt_t m;
    gt_util_null_init(m);
    decryption(m, order, ct, gm_state.sk, kpabe_type);
    free_ciphertext(ct, kpabe_type);
    gm_state.group_key = gt_util_to_aes_key(m, byte_length);
    gt_free(m);
}

void naive_kpabe_update_gm(naive_kpabe_gm_state& gm_state, bn_t order,
                                  const std::vector<unsigned char>& message, const abe_type kpabe_type) {
    const unsigned char action = message.at(0);
    if (action == 'j') {
        naive_kpabe_join_gm_old(gm_state, message);
    } else if (action == 'J') {
        naive_kpabe_join_gm_new(gm_state, message, kpabe_type);
    } else {
        naive_kpabe_leave_gm(gm_state, order, message, kpabe_type);
    }
}

void naive_kpabe_test(int size, kpabe_switcher::abe_type kpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(kpabe_type);

    const int join_user = size + 1;
    constexpr int leave_user = 1;
    naive_kpabe_gc_state gc_state{init_master_key(kpabe_type), init_public_key(kpabe_type)};
    std::map<ID_TYPE, naive_kpabe_gm_state> gm_states;

    naive_kpabe_setup(gc_state, gm_states, order, size, kpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    const naive_kpabe_join_message join_message = naive_kpabe_join_gc(gc_state, order, join_user, join_ind_key,
                                                                                    kpabe_type);
    for (auto& [id, gm_state] : gm_states) {
        naive_kpabe_update_gm(gm_state, order, join_message.old_member_message, kpabe_type);
    }
    gm_states[join_user].individual_key = join_ind_key;
    naive_kpabe_update_gm(gm_states.at(join_user), order, join_message.new_member_message, kpabe_type);

    const std::vector<unsigned char> leave_message = naive_kpabe_leave_gc(gc_state, order, leave_user, kpabe_type);
    free_secret_key(gm_states.at(leave_user).sk, kpabe_type);
    gm_states.erase(leave_user);
    for (auto& [id, gm_state] : gm_states) {
        naive_kpabe_update_gm(gm_state, order, leave_message, kpabe_type);
    }

    const std::vector<unsigned char>& gc_group_key = gc_state.group_key;
    for (const auto& [user, state] : gm_states) {
        if (std::memcmp(gc_group_key.data(), state.group_key.data(), byte_length) != 0) {
            std::cerr << "NAIVE DIRECT " << abe_type_string << ": The communication key of user " << user << " does not match the server communication key" << std::endl;
            exit(-1);
        }
    }
    std::cout << "NAIVE DIRECT " << abe_type_string << ": The server communication key matches all user communication keys" << std::endl;

    // Cleanup
    free_master_key(gc_state.mk, kpabe_type);
    free_public_key(gc_state.pk, kpabe_type);
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, kpabe_type);
    }
    bn_free(order);
}

void naive_kpabe_run_gc(int size, int precision, int repetitions, kpabe_switcher::abe_type kpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(kpabe_type);

    const int join_user = size + 1;
    const int leave_user = size;
    naive_kpabe_gc_state gc_state{init_master_key(kpabe_type), init_public_key(kpabe_type)};
    std::map<ID_TYPE, naive_kpabe_gm_state> gm_states;

    naive_kpabe_setup(gc_state, gm_states, order, size, kpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    long join_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        auto begin = std::chrono::steady_clock::now();
        naive_kpabe_join_gc(gc_state, order, join_user, join_ind_key, kpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.erase(join_user);
    }
    auto [mean, stddev] = calculate_mean_stddev(join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " GC Join Time: Avg: " << mean/1000 << " \\pm " << stddev/1000 << std::endl;

    long leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        auto begin = std::chrono::steady_clock::now();
        naive_kpabe_leave_gc(gc_state, order, leave_user, kpabe_type);
        auto end = std::chrono::steady_clock::now();
        leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.insert(leave_user);
    }
    auto [mean2, stddev2] = calculate_mean_stddev(leave_times, repetitions);
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " GC Leave Time: Avg: " << mean2/1000 << " \\pm " << stddev2/1000 << std::endl;

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, kpabe_type);
    }
    free_master_key(gc_state.mk, kpabe_type);
    free_public_key(gc_state.pk, kpabe_type);
    bn_free(order);
}

void naive_kpabe_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                                   int size, int repetitions, kpabe_switcher::abe_type kpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    int message_counter = 0;
    const std::string abe_type_string = type_to_string(kpabe_type);

    const int join_user_new = size + 1;
    const int join_user_old = size;
    const int leave_user = size - 1;
    naive_kpabe_gc_state gc_state{init_master_key(kpabe_type), init_public_key(kpabe_type)};
    std::map<ID_TYPE, naive_kpabe_gm_state> gm_states;

    naive_kpabe_setup(gc_state, gm_states, order, size, kpabe_type);

    for (int i = 0; i < repetitions; ++i) {
        const naive_kpabe_join_message join_message = naive_kpabe_join_gc(gc_state, order, join_user_new,
                                                                                        join_ind_key, kpabe_type);
        save_bytes_to_file(join_message.new_member_message, file_prefix + std::to_string(message_counter++));
        if (i != repetitions - 1) {
            gc_state.current_ids.erase(join_user_new);
        }
    }

    for (int i = 0; i < repetitions; ++i) {
        gc_state.current_ids.erase(join_user_old);
        const naive_kpabe_join_message join_message = naive_kpabe_join_gc(gc_state, order, join_user_old,
                                                                                        join_ind_key, kpabe_type);
        save_bytes_to_file(join_message.old_member_message, file_prefix + std::to_string(message_counter++));
    }
    gc_state.current_ids.erase(join_user_old);

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> leave_message = naive_kpabe_leave_gc(gc_state, order, leave_user, kpabe_type);
        save_bytes_to_files(leave_message, file_prefix + std::to_string(message_counter++), 5);
        gc_state.current_ids.insert(leave_user);
    }

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, kpabe_type);
    }
    free_master_key(gc_state.mk, kpabe_type);
    free_public_key(gc_state.pk, kpabe_type);
    bn_free(order);
}

void naive_kpabe_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                        int precision, int repetitions, kpabe_switcher::abe_type kpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    int message_counter = 0;
    const std::string abe_type_string = type_to_string(kpabe_type);

    naive_kpabe_gm_state gm_state{};
    gm_state.individual_key = join_ind_key;

    long join_new_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(file_prefix + std::to_string(message_counter++));
        auto begin = std::chrono::steady_clock::now();
        naive_kpabe_update_gm(gm_state, order, message, kpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_new_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        if (i != repetitions - 1) {
            free_secret_key(gm_state.sk, kpabe_type);
        }
    }
    auto [mean, stddev] = calculate_mean_stddev(join_new_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " GM New Join Time: Avg: " << mean/1000 << " \\pm " << stddev/1000 << std::endl;

    long join_old_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(file_prefix + std::to_string(message_counter++));
        auto begin = std::chrono::steady_clock::now();
        naive_kpabe_update_gm(gm_state, order, message, kpabe_type);
        auto end = std::chrono::steady_clock::now();
        join_old_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean2, stddev2] = calculate_mean_stddev(join_old_times, repetitions);
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " GM Old Join Time: Avg: " << mean2/1000 << " \\pm " << stddev2/1000 << std::endl;

    long leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_files(file_prefix + std::to_string(message_counter++), 5);
        auto begin = std::chrono::steady_clock::now();
        naive_kpabe_update_gm(gm_state, order, message, kpabe_type);
        auto end = std::chrono::steady_clock::now();
        leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean3, stddev3] = calculate_mean_stddev(leave_times, repetitions);
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " GM Leave Time: Avg: " << mean3/1000 << " \\pm " << stddev3/1000 << std::endl;

    // Cleanup
    free_secret_key(gm_state.sk, kpabe_type);
    bn_free(order);
}

void naive_kpabe_measure_byte_lengths(int size, kpabe_switcher::abe_type kpabe_type) {
    bn_t order;
    bn_util_null_init(order);
    pc_get_ord(order);

    const std::string abe_type_string = type_to_string(kpabe_type);

    const int join_user = size + 1;
    const int leave_user = size;
    naive_kpabe_gc_state gc_state{init_master_key(kpabe_type), init_public_key(kpabe_type)};
    std::map<ID_TYPE, naive_kpabe_gm_state> gm_states;

    naive_kpabe_setup(gc_state, gm_states, order, size, kpabe_type);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    const naive_kpabe_join_message join_message =  naive_kpabe_join_gc(gc_state, order, join_user, join_ind_key, kpabe_type);
    gc_state.current_ids.erase(join_user);
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " New Join Message Size: " << join_message.new_member_message.size() << std::endl;
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " Old Join Message Size: " << join_message.old_member_message.size() << std::endl;

    const std::vector<unsigned char> leave_message = naive_kpabe_leave_gc(gc_state, order, leave_user, kpabe_type);
    gc_state.current_ids.insert(leave_user);
    std::cout << "%" << "NAIVE DIRECT " << abe_type_string << " Leave Message Size: " << leave_message.size() << std::endl;

    // Cleanup
    for (auto& [user, state] : gm_states) {
        free_secret_key(state.sk, kpabe_type);
    }
    free_master_key(gc_state.mk, kpabe_type);
    free_public_key(gc_state.pk, kpabe_type);
    bn_free(order);
}