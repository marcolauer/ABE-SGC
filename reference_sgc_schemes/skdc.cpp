#include "skdc.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <vector>
#include <cstring>
#include <iomanip>

#include "../random.h"
#include "../crypto_functions/aes.h"

using ID_TYPE = uint16_t;

constexpr int byte_length = 16;

struct skdc_gc_state {
    std::vector<unsigned char> group_key;
    std::map<ID_TYPE, std::vector<unsigned char>> individual_keys;
    std::set<ID_TYPE> current_ids;
};

struct skdc_gm_state {
    std::vector<unsigned char> individual_key{}; // Shared only with GC
    std::vector<unsigned char> group_key{};
};

struct skdc_message {
    ID_TYPE receiver;
    std::vector<unsigned char> data{};
};


void skdc_setup(skdc_gc_state& gc_state, std::map<ID_TYPE, skdc_gm_state>& gm_states, const int num_users) {
    gc_state.group_key = byte_vector_random(byte_length);
    for (int i = 1; i <= num_users; ++i) {
        gc_state.current_ids.insert(i);
        skdc_gm_state& gm_state = gm_states[i];
        gm_state.individual_key = byte_vector_random(byte_length);
        gc_state.individual_keys[i] = gm_state.individual_key;
        gm_state.group_key = std::vector(gc_state.group_key);
    }
}

std::vector<skdc_message> skdc_join_gc(skdc_gc_state& gc_state, const ID_TYPE id,
                                                 const std::vector<unsigned char>& individual_key) {
    gc_state.group_key = byte_vector_random(byte_length);
    gc_state.current_ids.insert(id);
    gc_state.individual_keys[id] = individual_key;
    std::vector<skdc_message> result;
    result.reserve(gc_state.current_ids.size());
    for (const auto id2 : gc_state.current_ids) {
        result.push_back({id2, aes_encrypt(gc_state.individual_keys.at(id2), gc_state.group_key)});
    }
    return result;
}

std::vector<skdc_message> skdc_leave_gc(skdc_gc_state& gc_state, const ID_TYPE id) {
    gc_state.group_key = byte_vector_random(byte_length);
    gc_state.current_ids.erase(id);
    gc_state.individual_keys.erase(id);
    std::vector<skdc_message> result;
    result.reserve(gc_state.current_ids.size());
    for (const auto id2 : gc_state.current_ids) {
        result.push_back({id2, aes_encrypt(gc_state.individual_keys.at(id2), gc_state.group_key)});
    }
    return result;
}

void skdc_update_gm(skdc_gm_state& gm_state, const std::vector<unsigned char>& message) {
    const std::vector<unsigned char> plaintext = aes_decrypt(gm_state.individual_key, message);
    gm_state.group_key = plaintext;
}

void skdc_test(const int size) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;

    const int join_user = size + 1;
    constexpr int leave_user = 1;
    skdc_gc_state gc_state;
    std::map<ID_TYPE, skdc_gm_state> gm_states;

    skdc_setup(gc_state, gm_states, size);

    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);
    const std::vector<skdc_message> join_messages = skdc_join_gc(gc_state, join_user, join_ind_key);

    gm_states[join_user].individual_key = join_ind_key;
    for (const auto& [receiver, message] : join_messages) {
        skdc_update_gm(gm_states.at(receiver), message);
    }

    const std::vector<skdc_message> leave_messages = skdc_leave_gc(gc_state, leave_user);
    gm_states.erase(leave_user);

    for (const auto& [receiver, message] : leave_messages) {
        skdc_update_gm(gm_states.at(receiver), message);
    }

    const std::vector<unsigned char>& gc_group_key = gc_state.group_key;
    for (const auto& [user, state] : gm_states) {
        if (std::memcmp(gc_group_key.data(), state.group_key.data(), byte_length) != 0) {
            std::cerr << "SKDC: The communication key of user " << user << " does not match the server communication key" << std::endl;
            exit(-1);
        }
    }
    std::cout << "SKDC: The server communication key matches all user communication keys" << std::endl;
}

void skdc_run_gc(int size, int precision, int repetitions) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;

    const int user = size + 1;
    const int leave_user = size - 1;
    skdc_gc_state gc_state;
    std::map<ID_TYPE, skdc_gm_state> gm_states;
    skdc_setup(gc_state, gm_states, size);
    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    long gc_join_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        begin = std::chrono::steady_clock::now();
        const std::vector<skdc_message> join_messages = skdc_join_gc(gc_state, user, join_ind_key);
        end = std::chrono::steady_clock::now();
        gc_join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.erase(user);
    }
    auto [mean, stddev] = calculate_mean_stddev(gc_join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "SKDC GC Join Time: Avg: " << mean << " " << stddev << std::endl;

    long gc_leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        begin = std::chrono::steady_clock::now();
        const std::vector<skdc_message> leave_messages = skdc_leave_gc(gc_state, leave_user);
        end = std::chrono::steady_clock::now();
        gc_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
        gc_state.current_ids.insert(leave_user);
    }
    auto [mean2, stddev2] = calculate_mean_stddev(gc_leave_times, repetitions);
    std::cout << "%" << "SKDC GC Leave Time: " << mean2 << " " << stddev2 << std::endl;
}

void skdc_generate_messages(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                                 int size, int repetitions) {
    int message_counter = 0;
    const int user = size + 1;
    const int replace_user = size;
    const int leave_user = size - 1;
    skdc_gc_state gc_state;
    std::map<ID_TYPE, skdc_gm_state> gm_states;
    skdc_setup(gc_state, gm_states, size);

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<skdc_message> join_messages = skdc_join_gc(gc_state, user, join_ind_key);
        for (const auto& [receiver, message] : join_messages) {
            if (receiver == user) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
        if (i != repetitions - 1) {
            gc_state.current_ids.erase(user);
        }
    }
    gc_state.current_ids.erase(replace_user);

    for (int i = 0; i < repetitions; ++i) {
        const std::vector<skdc_message> leave_messages = skdc_leave_gc(gc_state, leave_user);
        for (const auto& [receiver, message] : leave_messages) {
            if (receiver == user) {
                save_bytes_to_file(message, file_prefix + std::to_string(message_counter++));
            }
        }
        gc_state.current_ids.insert(leave_user);
    }
}

void skdc_run_gm(const std::string& file_prefix, const std::vector<unsigned char>& join_ind_key,
                      const int precision, const int repetitions) {
    std::chrono::steady_clock::time_point begin;
    std::chrono::steady_clock::time_point end;

    int message_counter = 0;
    skdc_gm_state gm_state{};
    gm_state.individual_key = join_ind_key;

    long gm_join_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        skdc_update_gm(gm_state, message);
        end = std::chrono::steady_clock::now();
        gm_join_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean, stddev] = calculate_mean_stddev(gm_join_times, repetitions);
    std::cout << std::setprecision(precision) << std::fixed;
    std::cout << "%" << "SKDC GM Join Time: " << mean << " " << stddev << std::endl;

    long gm_leave_times[repetitions];
    for (int i = 0; i < repetitions; ++i) {
        const std::vector<unsigned char> message = load_bytes_from_file(
                file_prefix + std::to_string(message_counter++));
        begin = std::chrono::steady_clock::now();
        skdc_update_gm(gm_state, message);
        end = std::chrono::steady_clock::now();
        gm_leave_times[i] = std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count();
    }
    auto [mean2, stddev2] = calculate_mean_stddev(gm_leave_times, repetitions);
    std::cout << "%" << "SKDC GM Leave Time: " << mean2 << " " << stddev2 << std::endl;
}

void skdc_measure_byte_lengths(const int size) {
    const int join_user = size + 1;
    const int leave_user = size - 1;
    skdc_gc_state gc_state;
    std::map<ID_TYPE, skdc_gm_state> gm_states;
    skdc_setup(gc_state, gm_states, size);
    const std::vector<unsigned char> join_ind_key = byte_vector_random(byte_length);

    const std::vector<skdc_message> join_messages = skdc_join_gc(gc_state, join_user, join_ind_key);
    gc_state.current_ids.erase(join_user);
    std::cout << "%" << "SKDC Join Message Size: " << join_messages[0].data.size() << std::endl;

    const std::vector<skdc_message> leave_messages = skdc_leave_gc(gc_state, leave_user);
    gc_state.current_ids.insert(leave_user);
    std::cout << "%" << "SKDC Leave Message Size: " << leave_messages[0].data.size() << std::endl;
}