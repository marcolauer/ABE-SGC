#include "MSPMatrix.h"
#include <cmath>
#include <queue>
#include <iostream>
#include <algorithm>

#include "relic_util.h"
#include "util.h"

MSPMatrix *MSPMatrix::from_AOTree(AOTree *node, bn_t order) {
    int counter = 1;
    std::queue<std::pair<AOTree *, std::vector<bn_t *>>> queue;
    std::vector<std::pair<MSPAttribute, std::vector<bn_t *>>> attribute_vectors;
    auto start_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*start_val);
    bn_set_dig(*start_val, 1);
    queue.emplace(node, std::vector{start_val});
    while (!queue.empty()) {
        const std::pair<AOTree *, std::vector<bn_t *>>& pair = queue.front();
        AOTree* current = pair.first;
        std::vector<bn_t *> vec = pair.second;
        queue.pop();
        if (isType<AOAnd>(*current)) {
            const auto *nodeAnd = dynamic_cast<AOAnd *>(current);
            vec.reserve(counter + 1);
            while (vec.size() < counter) {
                auto zero_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
                bn_util_null_init(*zero_val);
                vec.push_back(zero_val);
            }
            auto one_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*one_val);
            bn_set_dig(*one_val, 1);
            vec.push_back(one_val);
            queue.emplace(nodeAnd->get_child1(), vec);
            std::vector<bn_t *> vec2;
            vec2.reserve(counter + 1);
            for (int i = 0; i < counter; ++i) {
                auto zero_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
                bn_util_null_init(*zero_val);
                vec2.push_back(zero_val);
            }
            auto minus_one_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*minus_one_val);
            bn_util_set_int_mod(*minus_one_val, -1, order);
            vec2.push_back(minus_one_val);
            queue.emplace(nodeAnd->get_child2(), vec2);
            ++counter;
        } else if (isType<AOOr>(*current)) {
            const auto *nodeOr = dynamic_cast<AOOr*>(current);
            queue.emplace(nodeOr->get_child1(), std::vector(vec));
            queue.emplace(nodeOr->get_child2(), bn_util_copy_vector(vec));
        } else {
            const auto *nodeAttribute = dynamic_cast<AOAttribute*>(current);
            attribute_vectors.push_back({{nodeAttribute->get_attribute(), nodeAttribute->get_occurrence()}, vec});
        }
    }
    const int matrix_size = attribute_vectors.size();
    std::vector<std::vector<bn_t *>> matrix(matrix_size);
    std::vector<MSPAttribute> row_to_attr;
    row_to_attr.reserve(matrix_size);
    for (int i = 0; i < matrix_size; ++i) {
        auto [attr, vec] = attribute_vectors[i];
        while (vec.size() < counter) {
            auto zero_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*zero_val);
            vec.push_back(zero_val);
        }
        matrix[i] = vec;
        row_to_attr.push_back(attr);
    }
    return new MSPMatrix(matrix_size, counter, matrix, row_to_attr);
}

std::optional<MSPMatrix *> MSPMatrix::from_AOTree_decrypt(AOTree *node, const std::vector<int> &attributes, bn_t order) {
    const MSPMatrix *msp = from_AOTree(node, order);
    std::vector<std::vector<bn_t *>> matrix;
    std::vector<MSPAttribute> row_to_attr;
    for (int i = 0; i < msp->rows; ++i) {
        const MSPAttribute mspAttr = msp->row_to_attr[i];
        const int attr = mspAttr.get_attribute();
        if (std::find(attributes.cbegin(), attributes.cend(), attr) != attributes.cend()) {
            matrix.push_back(msp->matrix[i]);
            row_to_attr.push_back(mspAttr);
        } else {
            bn_util_free_vector(msp->matrix[i]);
        }
    }
    const int matrix_size = matrix.size();
    const int cols = msp->cols;
    delete msp;
    if (matrix_size == 0) {
        return std::nullopt;
    }
    return new MSPMatrix(matrix_size, cols, matrix, row_to_attr);
}

// Helper function for function from_TTree
// Generates the following matrix with width t and height m:
//  1   1   1   ... 1
//  1   2   4   ... 2^(t-1)
//  1   3   9   ... 3^(t-1)
//  ... ... ... ... ...
//  1   n   n^2 ... n^(t-1)
std::vector<std::vector<bn_t *>> generate_tn_matrix(const int t, const int n, bn_t order) {
    std::vector<std::vector<bn_t *>> tn_matrix(n);
    bn_t temp;
    bn_util_null_init(temp);
    for (int i = 0; i < n; ++i) {
        const int ipp = i + 1;
        bn_set_dig(temp, 1);
        tn_matrix[i].reserve(t);
        for (int j = 0; j < t; ++j) {
            auto val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*val);
            bn_copy(*val, temp);
            tn_matrix[i].push_back(val);
            bn_util_mul_int_mod(temp, temp, ipp, order);
        }
    }
    bn_free(temp);
    return tn_matrix;
}

// Difference to generate_tn_matrix:
// Caches previously generated matrices => NOT SUITABLE FOR BENCHMARKING
std::vector<std::vector<bn_t *>> generate_tn_matrix_cache(const int t, const int n, bn_t order) {
    // Used for caching already requested tn matrices
    static std::vector<std::vector<bn_t *>> tn_cache_matrix;
    if (n > tn_cache_matrix.size()) {
        tn_cache_matrix.resize(n);
    }
    // Update the caching matrix
    bn_t temp;
    bn_util_null_init(temp);
    for (int i = 0; i < n; ++i) {
        const int ipp = i + 1;
        const int size = tn_cache_matrix[i].size();
        bn_util_set_int_mod(temp, ipp, order);
        bn_util_mxp_int(temp, temp, size, order);
        tn_cache_matrix[i].reserve(t);
        for (int j = size; j < t; ++j) {
            auto val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*val);
            bn_copy(*val, temp);
            tn_cache_matrix[i].push_back(val);
            bn_util_mul_int_mod(temp, temp, ipp, order);
        }
    }
    bn_free(temp);
    // Copy the needed parts from the caching matrix
    std::vector<std::vector<bn_t *>> result(n);
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < t; ++j) {
            auto val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*val);
            bn_copy(*val, *tn_cache_matrix[i][j]);
            result[i].push_back(val);
        }
    }
    return result;
}

std::optional<MSPMatrix *> MSPMatrix::from_TTree(TTree *node, const bool for_decrypt, const std::vector<int> &attributes, bn_t order) {
    if (isType<TThreshold>(*node)) {
        const auto tThreshold = dynamic_cast<TThreshold *>(node);
        const int t = tThreshold->get_t();
        const int n = tThreshold->get_n();
        const std::vector<std::vector<bn_t *>> vs = generate_tn_matrix(t, n, order);
        std::vector<std::vector<bn_t *>> matrix;
        int new_width = t;
        std::vector<MSPAttribute> row_to_attr;
        int valid = 0;
        for (int i = 0; i < n; ++i) {
            TTree *child = tThreshold->get_child(i);
            std::optional<MSPMatrix *> msp_opt = from_TTree(child, for_decrypt, attributes, order);
            std::vector<bn_t *> v = vs[i];
            if (!msp_opt.has_value()) {
                bn_util_free_vector(v);
                continue;
            }
            MSPMatrix *msp = msp_opt.value();
            for (int j = 0; j < msp->rows; ++j) {
                std::vector<bn_t *> row;
                row.reserve(new_width);
                std::vector<bn_t *>& child_row = msp->matrix[j];
                for (int k = 0; k < t; ++k) {
                    auto val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
                    bn_util_null_init(*val);
                    bn_util_mul_mod(*val, *v[k], *child_row[0], order);
                    row.push_back(val);
                }
                for (int k = 1; k < child_row.size(); ++k) {
                    auto val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
                    bn_util_null_init(*val);
                    bn_copy(*val, *child_row[k]);
                    row.push_back(val);
                }
                matrix.push_back(row);
            }
            bn_util_free_vector(v);
            new_width += msp->cols - 1;
            for (auto& row : matrix) {
                while (row.size() < new_width) {
                    auto zero_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
                    bn_util_null_init(*zero_val);
                    row.push_back(zero_val);
                }
            }
            std::vector<MSPAttribute> row_to_attr_child = msp->row_to_attr;
            row_to_attr.insert(row_to_attr.end(), row_to_attr_child.begin(), row_to_attr_child.end());
            ++valid;
            delete msp;
            if (for_decrypt && valid == t) {
                for (int j = i+1; j < n; ++j) {
                    bn_util_free_vector(vs[j]);
                }
                break;
            }
        }
        if (valid < t) {
            for (const auto& row : matrix) {
                bn_util_free_vector(row);
            }
            return std::nullopt;
        }
        return new MSPMatrix(matrix.size(), new_width, matrix, row_to_attr);
    }
    const auto tAttribute = dynamic_cast<TAttribute *>(node);
    if (for_decrypt &&
        find(attributes.begin(), attributes.end(), tAttribute->get_attribute()) == attributes.end()) {
        return std::nullopt;
    }
    auto one_val = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*one_val);
    bn_set_dig(*one_val, 1);
    return new MSPMatrix(1, 1, std::vector<std::vector<bn_t *>>{std::vector{one_val}}, std::vector<MSPAttribute>{{tAttribute->get_attribute(),
                                                                                                                  tAttribute->get_occurrence()}});
}


MSPMatrix *MSPMatrix::from_TTree(TTree *node, bn_t order) {
    return from_TTree(node, false, std::vector<int>(), order).value();
}

std::optional<MSPMatrix *> MSPMatrix::from_TTree_decrypt(TTree *node, const std::vector<int> &attributes, bn_t order) {
    return from_TTree(node, true, attributes, order);
}

MSPMatrix::MSPMatrix(const int rows, const int cols, std::vector<std::vector<bn_t *>> matrix, std::vector<MSPAttribute> row_to_attr) {
    this->rows = rows;
    this->cols = cols;
    this->matrix = std::move(matrix);
    this->row_to_attr = std::move(row_to_attr);
}

MSPMatrix::~MSPMatrix() {
    for (const auto& row : matrix) {
        for (const auto val : row) {
            bn_free(*val);
            free(val);
        }
    }
}

int MSPMatrix::get_rows() const {
    return rows;
}

int MSPMatrix::get_cols() const {
    return cols;
}

std::vector<bn_t *> MSPMatrix::get_row(const int i) {
    return matrix[i];
}

MSPAttribute MSPMatrix::get_attr_from_row(const int i) const {
    return row_to_attr[i];
}

void MSPMatrix::print() const {
    std::cout << "--------------------------" << std::endl;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            bn_print(*matrix[i][j]);
            std::cout << "\t";
        }
        std::cout << std::endl;
    }
    std::cout << "--------------------------" << std::endl;
}

MSPAttribute::MSPAttribute(const int attribute) {
    this->attribute = attribute;
    this->occurrence = 0;
}

MSPAttribute::MSPAttribute(const int attribute, const int occurrence) {
    this->attribute = attribute;
    this->occurrence = occurrence;
}

MSPAttribute::MSPAttribute(const MSPAttribute& node) {
    attribute = node.attribute;
    occurrence = node.occurrence;
}

bool MSPAttribute::operator <(const MSPAttribute& other) const {
    if (attribute == other.attribute) {
        return occurrence < other.occurrence;
    }
    return attribute < other.attribute;
}

int MSPAttribute::get_attribute() const {
    return attribute;
}

int MSPAttribute::get_occurrence() const {
    return occurrence;
}