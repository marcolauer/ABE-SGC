#include "util.h"
#include <cmath>
#include <fstream>
#include "serialize.h"
#include "config.h"

const std::string file_extension = ".bin";
#if MASTER_DEVICE == MASTER_PC
const std::string file_folder;
#elif MASTER_DEVICE == MASTER_ESP32
const std::string file_folder = "/storage/";
#endif

void bytes_xor(unsigned char *input1_result, const unsigned char *input2, const int byte_length) {
    for (int i = 0; i < byte_length; i++) {
        input1_result[i] ^= input2[i];
    }
}

std::vector<unsigned char> bytes_xor(const std::vector<unsigned char>& input1, const std::vector<unsigned char>& input2,
                                     const int byte_length) {
    std::vector<unsigned char> result(byte_length);
    for (int i = 0; i < byte_length; i++) {
        result[i] = input1.at(i) ^ input2.at(i);
    }
    return result;
}

double log_with_base(const double x, const int b) {
    return log2(x) / log2(b);
}

double log_with_base(const int x, const int b) {
    return log2(x) / log2(b);
}

void save_bytes_to_file(const std::vector<unsigned char>& bytes, const std::string& filename) {
    std::ofstream output(file_folder + filename + file_extension, std::ios::binary | std::ios::out | std::ios::trunc);
    output.write(reinterpret_cast<char *>(const_cast<unsigned char *>(bytes.data())), bytes.size());
    output.close();
}

void save_bytes_to_files(const std::vector<unsigned char>& bytes, const std::string& file_prefix, const int files) {
    const int size = bytes.size();
    const int partition_size = size / files;
    const int rest = size % files;
    int offset = 0;
    for (int i = 0; i < rest; ++i) {
        std::ofstream output(file_folder + file_prefix + "-" + std::to_string(i + 1) + file_extension, std::ios::binary | std::ios::out | std::ios::trunc);
        output.write(reinterpret_cast<char *>(const_cast<unsigned char *>(bytes.data() + offset)), partition_size + 1);
        output.close();
        offset += partition_size + 1;
    }
    for (int i = 0; i < files - rest; ++i) {
        std::ofstream output(file_folder + file_prefix + "-" + std::to_string(rest + i + 1) + file_extension, std::ios::binary | std::ios::out | std::ios::trunc);
        output.write(reinterpret_cast<char *>(const_cast<unsigned char *>(bytes.data() + offset)), partition_size);
        output.close();
        offset += partition_size;
    }
}

std::vector<unsigned char> load_bytes_from_file(const std::string& filename) {
    std::ifstream input(file_folder + filename + file_extension, std::ios::in | std::ios::binary);
    std::vector<unsigned char> bytes((std::istreambuf_iterator(input)), (std::istreambuf_iterator<char>()));
    input.close();
    return bytes;
}

std::vector<unsigned char> load_bytes_from_files(const std::string& file_prefix, const int files) {
    std::vector<unsigned char> result;
    for (int i = 0; i < files; ++i) {
        std::ifstream input(file_folder + file_prefix + "-" + std::to_string(i + 1) + file_extension, std::ios::in | std::ios::binary);
        std::vector<unsigned char> bytes((std::istreambuf_iterator(input)), (std::istreambuf_iterator<char>()));
        input.close();
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}