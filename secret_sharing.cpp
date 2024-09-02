#include "secret_sharing.h"
#include <queue>
#include <iostream>
#include <algorithm>
#include "util.h"
#include "relic_util.h"


std::vector<bn_t *> lagrange_coefficients(bn_t order, bn_t x, const std::vector<int>& S) {
    bn_t i, j, temp, temp2;
    bn_util_null_init(i);
    bn_util_null_init(j);
    bn_util_null_init(temp);
    bn_util_null_init(temp2);
    std::vector<bn_t *> results;
    results.reserve(S.size());
    for (const auto i_int : S) {
        auto result = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*result);
        bn_set_dig(*result, 1);
        bn_set_dig(i, i_int);
        for (const auto j_int : S) {
            bn_set_dig(j, j_int);
            if (i_int == j_int) {
                continue;
            }
            bn_util_sub_mod(temp, x, j, order);
            bn_util_sub_mod(temp2, i, j, order);
            bn_util_div_mod(temp, temp, temp2, order);
            bn_util_mul_mod(*result, *result, temp, order);
        }
        results.push_back(result);
    }
    bn_free(i);
    bn_free(j);
    bn_free(temp);
    bn_free(temp2);
    return results;
}

std::vector<bn_t *> lagrange_coefficients0(bn_t order, const std::vector<int>& S) {
    bn_t i, j, temp;
    bn_util_null_init(i);
    bn_util_null_init(j);
    bn_util_null_init(temp);
    std::vector<bn_t *> results;
    results.reserve(S.size());
    for (const auto i_int : S) {
        auto result = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*result);
        bn_set_dig(*result, 1);
        bn_set_dig(i, i_int);
        for (const auto j_int : S) {
            bn_set_dig(j, j_int);
            if (i_int == j_int) {
                continue;
            }
            bn_util_sub_mod(temp, j, i, order);
            bn_util_div_mod(temp, j, temp, order);
            bn_util_mul_mod(*result, *result, temp, order);
        }
        results.push_back(result);
    }
    bn_free(i);
    bn_free(j);
    bn_free(temp);
    return results;
}


std::vector<bn_t *> phuong_coefficients(bn_t order, const std::vector<int>& J) {
    const int n = J.size();
    bn_t xs[n];
    for (int i = 0; i < n; ++i) {
        bn_util_null_init(xs[i]);
        bn_util_set_int_mod(xs[i], J[i], order);
    }
    std::vector<bn_t *> es(n+1);
    bn_t ps[n];
    bn_t temp;
    bn_util_null_init(temp);
    es[n] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*es[n]);
    bn_set_dig(*es[n], 1);

    for (int i = 0; i < n; ++i) {
        const int e_index = n-i-1;
        if (i != 0) {
            for (int j = 0; j < n; ++j) {
                bn_util_mul_int_mod(xs[j], xs[j], -J[j], order);
            }
        }
        bn_util_null_init(ps[i]);
        es[e_index] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*es[e_index]);
        bn_util_sum_mod(ps[i], xs, n, order);
        for (int j = 0; j <= i; ++j) {
            bn_util_mul_mod(temp, *es[j+n-i], ps[j], order);
            bn_util_add_mod(*es[e_index], *es[e_index], temp, order);
        }
        bn_util_div_int_mod(*es[e_index], *es[e_index], i+1, order);
    }
    bn_free(temp);
    for (int i = 0; i < n; ++i) {
        bn_free(xs[i]);
        bn_free(ps[i]);
    }

    bool negate = true;
    for (int i = n-1; i >= 0; --i) {
        if (negate) {
            bn_util_neg_mod(*es[i], *es[i], order);
        }
        negate = !negate;
    }
    return es;
}

std::vector<bn_t *> generate_polynomial_shares_node(bn_t order, bn_t secret, const int t, const int n) {
    if (t > n) {
        std::cerr << "t larger than n in generate_polynomial_shares_node" << std::endl;
        exit(-1);
    }
    if (t < 1) {
        std::cerr << "t smaller than 1 in generate_polynomial_shares_node" << std::endl;
        exit(-1);
    }
    bn_t polynomial_coefficients[t];
    bn_util_null_init(polynomial_coefficients[0]);
    bn_copy(polynomial_coefficients[0], secret);
    for (int j = 1; j < t; ++j) {
        bn_util_null_init(polynomial_coefficients[j]);
        bn_rand_mod(polynomial_coefficients[j], order);
    }
    bn_t id;
    bn_util_null_init(id);
    std::vector<bn_t *> shares(n);
    for (int i = 0; i < n; ++i) {
        bn_set_dig(id, i+1);
        auto share = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*share);
        bn_evl(*share, polynomial_coefficients, id, order, t);
        shares[i] = share;
    }
    bn_free(id);
    for (int j = 0; j < t; ++j) {
        bn_free(polynomial_coefficients[j]);
    }
    return shares;
}

std::map<AOAttribute, bn_t *> generate_polynomial_shares_aotree(bn_t order, bn_t secret, const AOTree *policy) {
    TTree *ttree_policy = policy->to_TTree();
    std::map<TAttribute, bn_t *> ttree_result = generate_polynomial_shares_ttree(order, secret, ttree_policy);
    delete ttree_policy;
    std::map<AOAttribute, bn_t *> result;
    for (const auto& [tAttribute, share] : ttree_result) {
        AOAttribute aoAttribute(tAttribute.get_attribute(), tAttribute.get_occurrence());
        result[aoAttribute] = share;
    }
    return result;
}

std::map<TAttribute, bn_t *> generate_polynomial_shares_ttree(bn_t order, bn_t secret, TTree *policy) {
    std::map<TAttribute, bn_t *> result_map;
    std::queue<std::pair<TTree*, bn_t *>> queue;
    auto secret_duplicate = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*secret_duplicate)
    bn_copy(*secret_duplicate, secret);

    queue.emplace(policy, secret_duplicate);
    while (!queue.empty()) {
        const std::pair<TTree*, bn_t *> current_pair = queue.front();
        TTree* current = current_pair.first;
        bn_t *current_secret = current_pair.second;
        queue.pop();
        if (isType<TThreshold>(*current)) {
            const auto tThreshold = dynamic_cast<TThreshold*>(current);
            const int n = tThreshold->get_n();
            std::vector<TTree *> children = tThreshold->get_children();
            std::vector<bn_t *> shares = generate_polynomial_shares_node(order, *current_secret, tThreshold->get_t(), n);
            for (int i = 0; i < n; ++i) {
                queue.emplace(children[i], shares[i]);
            }
            bn_free(*current_secret);
            free(current_secret);
        } else {
            const auto tAttribute = dynamic_cast<TAttribute *>(current);
            result_map[TAttribute(*tAttribute)] = current_secret;
        }
    }
    return result_map;
}

std::tuple<bool, std::vector<AOAttribute>, std::set<AOTree *>> find_matching_attributes_aotree(AOTree *policy, const std::vector<int>& attributes) {
    if (isType<AOAnd>(*policy)) {
        const auto nodeAnd = dynamic_cast<AOAnd*>(policy);
        std::vector<AOAttribute> used_attributes;
        std::set<AOTree *> result_set;
        auto result = find_matching_attributes_aotree(nodeAnd->get_child1(), attributes);
        if (!get<0>(result)) {
            return make_tuple(false, used_attributes, result_set);
        }
        std::vector<AOAttribute>& attrs = get<1>(result);
        std::set<AOTree *>& node_used = get<2>(result);
        result = find_matching_attributes_aotree(nodeAnd->get_child2(), attributes);
        if (!get<0>(result)) {
            return make_tuple(false, used_attributes, result_set);
        }
        used_attributes.insert(used_attributes.end(), attrs.begin(), attrs.end());
        result_set.insert(node_used.begin(), node_used.end());
        attrs = get<1>(result);
        node_used = get<2>(result);
        used_attributes.insert(used_attributes.end(), attrs.begin(), attrs.end());
        result_set.insert(policy);
        result_set.insert(node_used.begin(), node_used.end());
        return make_tuple(true, used_attributes, result_set);
    }
    if (isType<AOOr>(*policy)) {
        const auto nodeOr = dynamic_cast<AOOr*>(policy);
        auto result = find_matching_attributes_aotree(nodeOr->get_child1(), attributes);
        if (get<0>(result)) {
            get<2>(result).insert(policy);
            return result;
        }
        result = find_matching_attributes_aotree(nodeOr->get_child2(), attributes);
        if (get<0>(result)) {
            get<2>(result).insert(policy);
            return result;
        }
        return make_tuple(false, std::vector<AOAttribute>(), std::set<AOTree *>());
    }
    const auto aoAttribute = dynamic_cast<AOAttribute *>(policy);
    if (std::find(attributes.begin(), attributes.end(), aoAttribute->get_attribute()) != attributes.end()) {
        return make_tuple(true, std::vector{AOAttribute(*aoAttribute)}, std::set{policy});
    }
    return make_tuple(false, std::vector<AOAttribute>(), std::set<AOTree *>());
}

std::tuple<bool, std::vector<TAttribute>, std::set<TTree *>> find_matching_attributes_ttree(TTree *policy, const std::vector<int>& attributes) {
    if (isType<TThreshold>(*policy)) {
        const auto tThreshold = dynamic_cast<TThreshold*>(policy);
        std::vector<TAttribute> used_attributes;
        std::set<TTree *> result_set;
        int countdown = tThreshold->get_t();
        const int n = tThreshold->get_n();
        for (int i = 0; i < n; ++i) {
            auto result = find_matching_attributes_ttree(tThreshold->get_child(i), attributes);
            if (get<0>(result)) {
                std::vector<TAttribute>& attrs = get<1>(result);
                std::set<TTree *>& node_used = get<2>(result);
                used_attributes.insert(used_attributes.end(), attrs.begin(), attrs.end());
                result_set.insert(node_used.begin(), node_used.end());
                --countdown;
                if (countdown == 0) {
                    result_set.insert(policy);
                    return make_tuple(true, used_attributes, result_set);
                }
            } else if (countdown > n - i - 1) {
                return make_tuple(false, std::vector<TAttribute>(), std::set<TTree *>());
            }
        }
        return make_tuple(false, std::vector<TAttribute>(), std::set<TTree *>());
    }
    const auto tAttribute = dynamic_cast<TAttribute *>(policy);
    if (std::find(attributes.begin(), attributes.end(), tAttribute->get_attribute()) != attributes.end()) {
        return make_tuple(true, std::vector{TAttribute(*tAttribute)}, std::set{policy});
    }
    return make_tuple(false, std::vector<TAttribute>(), std::set<TTree *>());
}

std::map<AOAttribute, bn_t *> generate_coefficients_aotree(bn_t order, AOTree *policy, const std::set<AOTree *>& used_nodes) {
    std::map<AOAttribute, bn_t *> result_map;
    std::queue<std::pair<AOTree*, bn_t *>> queue;
    if (!used_nodes.contains(policy)) {
        std::cerr << "The passed policy wasn't fulfilled" << std::endl;
        exit(-1);
    }
    auto start_value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*start_value);
    bn_set_dig(*start_value, 1);
    queue.emplace(policy, start_value);
    while (!queue.empty()) {
        const std::pair<AOTree*, bn_t *> current_pair = queue.front();
        AOTree* current = current_pair.first;
        bn_t *current_element = current_pair.second;
        queue.pop();
        if (isType<AOAnd>(*current)) {
            const auto aoAnd = dynamic_cast<AOAnd*>(current);
            auto elem = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*elem);
            bn_util_mul_int_mod(*elem, *current_element, 2, order);
            queue.emplace(aoAnd->get_child1(), elem);
            bn_util_neg_mod(*current_element, *current_element, order);
            queue.emplace(aoAnd->get_child2(), current_element);
        } else if (isType<AOOr>(*current)) {
            const auto aoOr = dynamic_cast<AOOr*>(current);
            if (used_nodes.contains(aoOr->get_child1())) {
                queue.emplace(aoOr->get_child1(), current_element);
            } else {
                queue.emplace(aoOr->get_child2(), current_element);
            }
        } else {
            const auto aoAttribute = dynamic_cast<AOAttribute *>(current);
            result_map[AOAttribute(*aoAttribute)] = current_element;
        }
    }
    return result_map;
}

std::map<TAttribute, bn_t *> generate_coefficients_ttree(bn_t order, TTree *policy, const std::set<TTree *>& used_nodes) {
    std::map<TAttribute, bn_t *> result_map;
    std::queue<std::pair<TTree*, bn_t *>> queue;
    if (!used_nodes.contains(policy)) {
        std::cerr << "The passed policy wasn't fulfilled" << std::endl;
        exit(-1);
    }
    auto start_value = static_cast<bn_t *>(malloc(sizeof(bn_t)));
    bn_util_null_init(*start_value);
    bn_set_dig(*start_value, 1);
    queue.emplace(policy, start_value);
    while (!queue.empty()) {
        const std::pair<TTree*, bn_t *> current_pair = queue.front();
        TTree *current = current_pair.first;
        bn_t *current_element = current_pair.second;
        queue.pop();
        if (isType<TThreshold>(*current)) {
            const auto tThreshold = dynamic_cast<TThreshold *>(current);
            const int t = tThreshold->get_t();
            const int n = tThreshold->get_n();
            std::vector<int> vec;
            vec.reserve(t);
            for (int i = 0; i < n; ++i) {
                if (used_nodes.contains(tThreshold->get_child(i))) {
                    vec.push_back(i+1);
                }
            }
            std::vector<bn_t *> coeffs = lagrange_coefficients0(order, vec);
            for (int i = 0; i < t; ++i) {
                bn_util_mul_mod(*coeffs[i], *coeffs[i], *current_element, order);
                queue.emplace(tThreshold->get_child(vec[i] - 1), coeffs[i]);
            }
            bn_free(*current_element);
            free(current_element);
        } else {
            const auto tAttribute = dynamic_cast<TAttribute *>(current);
            result_map[TAttribute(*tAttribute)] = current_element;
        }
    }
    return result_map;
}

std::map<MSPAttribute, bn_t *> solve_msp(bn_t order, MSPMatrix *msp) {
    int curr_row = 0;
    int curr_col = 0;
    int pivot_col = 0;
    const int colsmm = msp->get_rows();
    const size_t cols = colsmm + 1;
    const size_t rows = msp->get_cols();
    bn_t *matrix[rows][cols];
    std::vector<MSPAttribute> attrs;
    attrs.reserve(colsmm);
    for (int i = 0; i < colsmm; ++i) {
        attrs.push_back(msp->get_attr_from_row(i));
        for (int j = 0; j < rows; ++j) {
            std::vector<bn_t *> row = msp->get_row(i);
            matrix[j][i] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*matrix[j][i])
            bn_copy(*matrix[j][i], *row[j]);
        }
    }
    for (int i = 0; i < rows; ++i) {
        matrix[i][colsmm] = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*matrix[i][colsmm]);
        if (i == 0) {
            bn_set_dig(*matrix[i][colsmm], 1);
        } else {
            bn_zero(*matrix[i][colsmm]);
        }
    }

    bn_t temp, temp2;
    bn_util_null_init(temp);
    bn_util_null_init(temp2);
    while (true) {
        if (curr_col == cols || curr_row == rows) {
            break;
        }
        int row = -1;
        for (int i = curr_row; i < rows; ++i) {
            if (!bn_is_zero(*matrix[i][curr_col])) {
                row = i;
                break;
            }
        }
        if (row != -1) {
            for (int i = 0; i < cols; ++i) {
                std::swap(matrix[curr_row][i], matrix[row][i]);
            }
            if (bn_cmp_dig(*matrix[curr_row][curr_col], 1) != RLC_EQ) {
                for (int i = curr_col + 1; i < cols; ++i) {
                    bn_util_div_mod(*matrix[curr_row][i], *matrix[curr_row][i], *matrix[curr_row][curr_col], order);
                }
                bn_set_dig(*matrix[curr_row][curr_col], 1);
            }
            for (int i = curr_row + 1; i < rows; ++i) {
                if (!bn_is_zero(*matrix[i][curr_col])) {
                    bn_copy(temp, *matrix[i][curr_col]);
                    for (int j = curr_col; j < cols; ++j) {
                        bn_util_mul_mod(temp2, temp, *matrix[curr_row][j], order);
                        bn_util_sub_mod(*matrix[i][j], *matrix[i][j], temp2, order);
                    }
                }
            }
            for (int i = 0; i < curr_row; ++i) {
                if (!bn_is_zero(*matrix[i][curr_col])) {
                    bn_copy(temp, *matrix[i][curr_col]);
                    for (int j = curr_col; j < cols; ++j) {
                        bn_util_mul_mod(temp2, temp, *matrix[curr_row][j], order);
                        bn_util_sub_mod(*matrix[i][j], *matrix[i][j], temp2, order);
                    }
                }
            }
            pivot_col = curr_col;
            ++curr_row;
        }
        ++curr_col;
    }
    bn_free(temp);
    bn_free(temp2);
    if (pivot_col == colsmm) {
        std::cerr << "Decryption not possible" << std::endl;
        exit(-1);
    }

    std::map<MSPAttribute, bn_t *> result;
    std::vector<bn_t *> solution;
    solution.reserve(colsmm);
    curr_col = 0;
    for (int i = 0; i < rows; ++i) {
        while (bn_is_zero(*matrix[i][curr_col])) {
            ++curr_col;
            auto zero = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*zero);
            solution.push_back(zero);
            if (curr_col == cols) {
                goto outer;
            }
        }
        if (bn_cmp_dig(*matrix[i][curr_col], 1) == RLC_EQ) {
            ++curr_col;
            auto elem = static_cast<bn_t *>(malloc(sizeof(bn_t)));
            bn_util_null_init(*elem);
            bn_copy(*elem, *matrix[i][cols - 1]);
            solution.push_back(elem);
        } else {
            std::cerr << "Error" << std::endl;
            exit(-1);
        }
        if (curr_col == cols) {
            break;
        }
    }
    outer:
    while (solution.size() < colsmm)  {
        auto zero = static_cast<bn_t *>(malloc(sizeof(bn_t)));
        bn_util_null_init(*zero);
        solution.push_back(zero);
    }
    while (solution.size() > colsmm)  {
        bn_free(*solution.back());
        free(solution.back());
        solution.pop_back();
    }
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            bn_free(*matrix[i][j]);
            free(matrix[i][j]);
        }
    }
    for (int i = 0; i < colsmm; ++i) {
        result[attrs[i]] = solution[i];
    }
    return result;
}