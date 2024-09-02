#ifndef MASTER_UTIL_H
#define MASTER_UTIL_H

#include <cmath>
#include <numeric>
#include <vector>
#include <unordered_set>
#include <typeinfo>
#include <algorithm>
#include <string>

// This header file contains a wide variety of utility functions used in the project.

/**
 * XORs two byte arrays.
 * @param[in,out] input1_result the first input byte array and the result byte array.
 * @param[in] input2 the second input byte array.
 * @param[in] byte_length the length of both byte arrays.
 */
void bytes_xor(unsigned char *input1_result, const unsigned char *input2, int byte_length);

/**
 * XORs two byte vectors.
 * @param[in] input1 the first input byte vector.
 * @param[in] input2 the second input byte vector.
 * @param[in] byte_length the length of both byte vectors.
 * @returns the resulting byte vector.
 */
std::vector<unsigned char> bytes_xor(const std::vector<unsigned char>& input1, const std::vector<unsigned char>& input2,
                                     int byte_length);

/**
 * Computes the intersection of a unordered set and a vector.
 * @tparam T the type contained in the set and vector.
 * @param[in] uset the input set.
 * @param[in] vec the input vector.
 * @returns the resulting byte vector.
 */
template <typename T>
std::vector<T> uset_vector_intersection(std::unordered_set<T> uset, std::vector<T> vec) {
    std::vector<T> res;
    for (auto t : vec)
        if (uset.contains(t)) {
            res.push_back(t);
            uset.erase(t);
        }
    return res;
}

/**
 * Computes the intersection of two vectors.
 * @tparam T the type contained in the vectors.
 * @param[in] input1 the first input vector.
 * @param[in] input2 the second input vector.
 * @returns the result vector.
 */
template <typename T>
std::vector<T> vector_intersection(std::vector<T> input1, std::vector<T> input2) {
    std::unordered_set<T> uset(input1.begin(), input1.end());
    return uset_vector_intersection(uset, input2);
}

/**
 * Checks if the input has type T.
 * @tparam T the type.
 * @tparam K do not specify - the true type of k, which is derived automatically.
 * @param[in] k the value whose type is to be checked.
 * @returns true if k has type T, false otherwise.
 */
template<typename T, typename K>
bool isType(const K &k) {
    return typeid(T).hash_code() == typeid(k).hash_code();
}

/**
 * Calculates the logarithm of the double x to the base b.
 * @param[in] x the input value.
 * @param[in] b the base.
 * @returns the result of the logarithm.
 */
double log_with_base(double x, int b);

/**
 * Calculates the logarithm of the integer int x to the base b.
 * @param[in] x the input value.
 * @param[in] b the base.
 * @returns the result of the logarithm.
 */
double log_with_base(int x, int b);


/**
 * Calculates the mean and standard deviation of an array of numeric values.
 * @param[in] vals the input array.
 * @param[in] length the array length.
 * @returns the mean and the standard deviation values.
 */
template<typename TYPE, std::enable_if_t<std::is_arithmetic_v<TYPE>, bool> = true>
std::pair<double, double> calculate_mean_stddev(TYPE *vals, int length) {
    const double mean = static_cast<double>(std::accumulate(vals, vals + length, 0)) / length;
    std::vector<double> diff(length);
    transform(vals, vals + length, diff.begin(), [mean](const double x) {return x - mean;});
    const double sq_sum = std::inner_product(diff.begin(), diff.end(), diff.begin(), 0.0);
    const double stddev = std::sqrt(sq_sum / length);
    return {mean, stddev};
}

/**
 * Writes a byte vector to a file.
 * @param[in] bytes the byte vector to write to the file.
 * @param[in] filename the file to write to.
 */
void save_bytes_to_file(const std::vector<unsigned char>& bytes, const std::string& filename);

/**
 * Writes a byte vector to multiple files.
 * @param[in] bytes the byte vector to write to the files.
 * @param[in] file_prefix the prefix that the files that are written to are named before an enumeration.
 */
void save_bytes_to_files(const std::vector<unsigned char>& bytes, const std::string& file_prefix, int files);

/**
 * Reads a byte vector from a file.
 * @param[in] filename the file to read from.
 * @returns the byte vector read from the file.
 */
std::vector<unsigned char> load_bytes_from_file(const std::string& filename);

/**
 * Reads a byte vector from multiple files.
 * @param[in] file_prefix the prefix that the files to be read from are named before an enumeration.
 * @returns the byte vector read from the files.
 */
std::vector<unsigned char> load_bytes_from_files(const std::string& file_prefix, int files);

#endif //MASTER_UTIL_H
