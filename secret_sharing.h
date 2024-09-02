#ifndef MASTER_SECRET_SHARING_H
#define MASTER_SECRET_SHARING_H

#include <vector>
#include <map>
#include <set>
#include "AOTree.h"
#include "TTree.h"
#include "MSPMatrix.h"
extern "C" {
#include <relic.h>
}

// This header file contains functions used for secret sharing.

/**
 * Computes the coefficients for the lagrange interpolation of a polynomial in a finite field.
 * This is used in Shamirs Secret Sharing.
 * @param[in] order the order of the finite field.
 * @param[in] x the x-coordinate of the point to be interpolated.
 * @param[in] S the x-coordinates of the given points.
 * @returns a vector containing the coefficients of the lagrange polynomial.
 */
std::vector<bn_t *> lagrange_coefficients(bn_t order, bn_t x, const std::vector<int>& S);

/**
 * Computes the coefficients for the lagrange interpolation of a polynomial in a finite field.
 * This is used in Shamirs Secret Sharing.
 * This function assumes that the x-coordinate of the point to be interpolated is 0.
 * @param[in] order the order of the finite field.
 * @param[in] S the x-coordinates of the given points.
 * @returns a vector containing the coefficients of the lagrange polynomial.
 */
std::vector<bn_t *> lagrange_coefficients0(bn_t order, const std::vector<int>& S);

/**
 * Computes the coefficients needed for the ABE schemes in
 * <a href="http://dx.doi.org/10.1007/978-3-319-24177-7_13">Phuong et al.'s paper</a>.
 * Made efficient by using Newtons identities.
 * @param[in] order the order of the finite field.
 * @param[in] J the wildcard positions.
 * @returns a vector containing the coefficients.
 */
std::vector<bn_t *> phuong_coefficients(bn_t order, const std::vector<int>& J);

/**
 * Generates random shares for Shamirs Secret Sharing.
 * @param[in] order the order of the finite field.
 * @param[in] secret the secret value that can be recovered with sufficient shares.
 * @param[in] t the number of shares required to recover the secret.
 * @param[in] n the number of generated shares.
 * @returns a vector containing the shares.
 */
std::vector<bn_t *> generate_polynomial_shares_node(bn_t order, bn_t secret, int t, int n);

/**
 * Generates random shares for an AND-OR-Gate Access Tree.
 * @param[in] order the order of the finite field.
 * @param[in] secret the secret value that can be recovered with matching shares.
 * @param[in] policy the AND-OR-Gate Access Tree.
 * @returns a map mapping the attributes to the shares.
 */
std::map<AOAttribute, bn_t *> generate_polynomial_shares_aotree(bn_t order, bn_t secret, const AOTree *policy);

/**
 * Generates random shares for a Threshold-Gate Access Tree.
 * @param[in] order the order of the finite field.
 * @param[in] secret the secret value that can be recovered with matching shares.
 * @param[in] policy the AND-OR-Gate Access Tree.
 * @returns a map mapping the attributes to the shares.
 */
std::map<TAttribute, bn_t *> generate_polynomial_shares_ttree(bn_t order, bn_t secret, TTree *policy);

/**
 * Checks if a users attributes fulfill the access policy and, if so, return the used attributes and nodes of the access
 * tree.
 * @param[in] policy the access policy in form of an AND-OR-Gate Access Tree.
 * @param[in] attributes the user's attributes.
 * @returns a tuple containing three objects: A boolean showing whether the policy is fulfilled, a vector containing the
 *      used attributes, and a set containing all used nodes of the access tree.
 */
std::tuple<bool, std::vector<AOAttribute>, std::set<AOTree *>> find_matching_attributes_aotree(AOTree *policy, const std::vector<int>& attributes);

/**
 * Checks if a users attributes fulfill the access policy and, if so, return the used attributes and nodes of the access
 * tree.
 * @param[in] policy the access policy in form of an Threshold-Gate Access Tree.
 * @param[in] attributes the user's attributes.
 * @returns a tuple containing three objects: A boolean showing whether the policy is fulfilled, a vector containing the
 *      used attributes, and a set containing all used nodes of the access tree.
 */
std::tuple<bool, std::vector<TAttribute>, std::set<TTree *>> find_matching_attributes_ttree(TTree *policy, const std::vector<int>& attributes);

/**
 * Computes the lagrange interpolation coefficients needed for recovering a secret value that was hidden with an
 * AND-OR-Gate Access Tree.
 * Slightly faster than generate_coefficients_ttree (no need to call lagrange_coefficients0).
 * @param[in] order the order of the finite field.
 * @param[in] policy the AND-OR-Gate Access Tree.
 * @param[in] used_nodes a set containing all used nodes of the access tree.
 * @returns a map mapping the attributes to the coefficients.
 */
std::map<AOAttribute, bn_t *> generate_coefficients_aotree(bn_t order, AOTree *policy, const std::set<AOTree *>& used_nodes);

/**
 * Computes the lagrange interpolation coefficients needed for recovering a secret value that was hidden with an
 * Threshold-Gate Access Tree.
 * @param[in] order the order of the finite field.
 * @param[in] policy the Threshold-Gate Access Tree.
 * @param[in] used_nodes a set containing all used nodes of the access tree.
 * @returns a map mapping the attributes to the coefficients.
 */
std::map<TAttribute, bn_t *> generate_coefficients_ttree(bn_t order, TTree *policy, const std::set<TTree *>& used_nodes);

/**
 * Performs the gaussian elimination on the MSP matrix to obtain the coefficients needed for recovering a secret value
 * that was hidden with a MSP matrix
 * @param[in] order the order of the finite field.
 * @param[in] msp the MSP matrix.
 * @returns a map mapping the attributes of the MS matrix to the coefficients
 */
std::map<MSPAttribute, bn_t *> solve_msp(bn_t order, MSPMatrix *msp);

#endif //MASTER_SECRET_SHARING_H
