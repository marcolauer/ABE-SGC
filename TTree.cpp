#include "TTree.h"
#include <iostream>
#include "util.h"

TThreshold::TThreshold(const int t, const int n, std::vector<TTree *> children) {
    if (t > n) {
        std::cerr << "t larger than n in threshold node" << std::endl;
        exit(-1);
    }
    if (t < 1) {
        std::cerr << "t smaller than 1 in threshold node" << std::endl;
        exit(-1);
    }
    this->t = t;
    this->n = n;
    this->children = std::move(children);
}

TThreshold::TThreshold(const TThreshold& node) {
    t = node.t;
    n = node.n;
    children.reserve(node.children.size());
    for (const auto child: node.children) {
        if (isType<TThreshold>(*child)) {
            children.push_back(new TThreshold(*dynamic_cast<TThreshold *>(child)));
        } else {
            children.push_back(new TAttribute(*dynamic_cast<TAttribute *>(child)));
        }
    }
}

TThreshold::~TThreshold() {
    for (const auto c : children) {
        delete c;
    }
}

TTree *TThreshold::clone() const {
    return new TThreshold(*this);
}

int TThreshold::get_t() const {
    return t;
}

int TThreshold::get_n() const {
    return n;
}

TTree *TThreshold::get_child(const int i) const {
    return children.at(i);
}

std::vector<TTree *> TThreshold::get_children() {
    return children;
}

int TThreshold::get_max_occurrence() const {
    std::vector<int> max_occs;
    std::transform(children.begin(), children.end(), std::back_inserter(max_occs), [](const TTree *tree){return tree->get_max_occurrence();});
    return *std::max_element(max_occs.begin(), max_occs.end());
}

TAttribute::TAttribute(const int attribute) {
    this->attribute = attribute;
    this->occurrence = 0;
}

TAttribute::TAttribute(const int attribute, const int occurrence) {
    this->attribute = attribute;
    this->occurrence = occurrence;
}

TAttribute::TAttribute(const TAttribute& node) {
    attribute = node.attribute;
    occurrence = node.occurrence;
}

TAttribute::~TAttribute() = default;

bool TAttribute::operator <(const TAttribute& other) const {
    if (attribute == other.attribute) {
        return occurrence < other.occurrence;
    }
    return attribute < other.attribute;
}

TTree *TAttribute::clone() const {
    return new TAttribute(*this);
}

int TAttribute::get_attribute() const {
    return attribute;
}

int TAttribute::get_occurrence() const {
    return occurrence;
}

int TAttribute::get_max_occurrence() const {
    return occurrence;
}