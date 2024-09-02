#include "AOTree.h"
#include "util.h"

AOAnd::AOAnd(AOTree *node1, AOTree *node2) {
    this->child1 = node1;
    this->child2 = node2;
}

AOAnd::AOAnd(const AOAnd& node) {
    AOTree* child1 = node.get_child1();
    if (isType<AOAnd>(*child1)) {
        this->child1 = new AOAnd(*dynamic_cast<AOAnd *>(child1));
    } else if (isType<AOOr>(*child1)) {
        this->child1 = new AOOr(*dynamic_cast<AOOr *>(child1));
    } else {
        this->child1 = new AOAttribute(*dynamic_cast<AOAttribute *>(child1));
    }
    AOTree* child2 = node.get_child2();
    if (isType<AOAnd>(*child2)) {
        this->child2 = new AOAnd(*dynamic_cast<AOAnd *>(child2));
    } else if (isType<AOOr>(*child2)) {
        this->child2 = new AOOr(*dynamic_cast<AOOr *>(child2));
    } else {
        this->child2 = new AOAttribute(*dynamic_cast<AOAttribute *>(child2));
    }
}

AOAnd::~AOAnd() {
    delete child1;
    delete child2;
}

AOTree *AOAnd::clone() const {
    return new AOAnd(*this);
}

AOTree *AOAnd::get_child1() const {
    return child1;
}

AOTree *AOAnd::get_child2() const {
    return child2;
}

TTree *AOAnd::to_TTree() const {
    return new TThreshold(2, 2, std::vector{get_child1()->to_TTree(), get_child2()->to_TTree()});
}

AOOr::AOOr(AOTree *node1, AOTree *node2) {
    this->child1 = node1;
    this->child2 = node2;
}

AOOr::AOOr(const AOOr& node) {
    const AOTree* child1 = node.get_child1();
    if (isType<AOAnd>(*child1)) {
        this->child1 = new AOAnd(*dynamic_cast<AOAnd *>(node.get_child1()));
    } else if (isType<AOOr>(*child1)) {
        this->child1 = new AOOr(*dynamic_cast<AOOr *>(node.get_child1()));
    } else {
        this->child1 = new AOAttribute(*dynamic_cast<AOAttribute *>(node.get_child1()));
    }
    const AOTree* child2 = node.get_child2();
    if (isType<AOAnd>(*child2)) {
        this->child2 = new AOAnd(*dynamic_cast<AOAnd *>(node.get_child2()));
    } else if (isType<AOOr>(*child2)) {
        this->child2 = new AOOr(*dynamic_cast<AOOr *>(node.get_child2()));
    } else {
        this->child2 = new AOAttribute(*dynamic_cast<AOAttribute *>(node.get_child2()));
    }
}

AOOr::~AOOr() {
    delete child1;
    delete child2;
}

AOTree *AOOr::clone() const {
    return new AOOr(*this);
}

AOTree *AOOr::get_child1() const {
    return child1;
}

AOTree *AOOr::get_child2() const {
    return child2;
}

TTree *AOOr::to_TTree() const {
    return new TThreshold(1, 2, std::vector{get_child1()->to_TTree(), get_child2()->to_TTree()});
}

AOAttribute::AOAttribute(const int attribute) {
    this->attribute = attribute;
    this->occurrence = 0;
}

AOAttribute::AOAttribute(const int attribute, const int occurrence) {
    this->attribute = attribute;
    this->occurrence = occurrence;
}

AOAttribute::AOAttribute(const AOAttribute& node) {
    attribute = node.attribute;
    occurrence = node.occurrence;
}

AOAttribute::~AOAttribute() = default;

bool AOAttribute::operator <(const AOAttribute& other) const {
    if (attribute == other.attribute) {
        return occurrence < other.occurrence;
    }
    return attribute < other.attribute;
}

AOTree *AOAttribute::clone() const {
    return new AOAttribute(*this);
}

int AOAttribute::get_attribute() const {
    return attribute;
}

int  AOAttribute::get_occurrence() const {
    return occurrence;
}

TTree *AOAttribute::to_TTree() const {
    return new TAttribute(attribute, occurrence);
}