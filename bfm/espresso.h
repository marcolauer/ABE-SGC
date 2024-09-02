#ifndef MASTER_ESPRESSO_H
#define MASTER_ESPRESSO_H

#include <bitset>
#include <vector>
#include <fstream>

/**
 * An interface function that creates input data files for the Espresso logic minimizer program, calls it via the
 * command line, and loads the data from the result file.
 * @tparam Nbits the maximal bit-length of the input values.
 * @tparam INT_TYPE the type of integers used as the input values, e.g. uint8_t, uint16_t, ... .
 * @param on_values the products that should evaluate to true.
 * @param dc_values the products that are allowed to evaluate to true or false (dc = don't care).
 * @returns The resulting sum-of-products (SOP) expression in form of a vector of string
 *      (each string represents a product).
 */
template<size_t Nbits, typename INT_TYPE, std::enable_if_t<std::is_integral_v<INT_TYPE>, bool> = true>
std::vector<std::string> espresso(const std::vector<INT_TYPE>& on_values, const std::vector<INT_TYPE>& dc_values) {
    std::ofstream output("espresso_input.temp", std::ios::out | std::ios::trunc);
    output << ".i " << Nbits << std::endl;
    output << ".o 1" << std::endl;
    for (const auto on_value : on_values) {
        std::bitset<Nbits> bits(on_value);
        for (int i = 0; i < Nbits; ++i) {
            output << bits[i];
        }
        output << " 1" << std::endl;
    }
    for (const auto dc_value : dc_values) {
        std::bitset<Nbits> bits(dc_value);
        for (int i = 0; i < Nbits; ++i) {
            output << bits[i];
        }
        output << " -" << std::endl;
    }
    output << ".e" << std::endl;
    output.close();

    system("espresso espresso_input.temp > espresso_output.temp");
    std::ifstream input ("espresso_output.temp", std::ios::in);

    std::vector<std::string> result;
    std::string line;
    getline(input, line);
    getline(input, line);
    getline(input, line, ' ');
    int num_results;
    input >>  num_results;
    getline(input, line);
    for (int i = 0; i < num_results; ++i) {
        getline(input, line, ' ');
        result.push_back(line);
        getline(input, line);
    }
    input.close();
    return result;
}

#endif //MASTER_ESPRESSO_H
