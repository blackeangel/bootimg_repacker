// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/fdt.hpp"

#include <cstdio>
#include <cstring>
#include <deque>
#include <unordered_map>

#include "abr/dtb.hpp"
#include "abr/textquote.hpp"

namespace abr::fdt {

namespace {

constexpr uint32_t kBeginNode = 1;
constexpr uint32_t kEndNode = 2;
constexpr uint32_t kProp = 3;
constexpr uint32_t kNop = 4;
constexpr uint32_t kEnd = 9;

constexpr size_t kMaxName = 255;          // a node or property name (the specification says 31; Linux has longer ones)
constexpr size_t kMaxStrings = 1u << 20;  // the strings block
constexpr size_t kHeaderV17 = 40;
constexpr size_t kHeaderV16 = 36;

[[noreturn]] void bad(const std::string& what) { throw FormatError("flattened device tree: " + what); }

std::string hex32(uint32_t v) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08x", v);
    return buf;
}

// A name for a message: it comes from the blob, so what a terminal would act on is written as an escape.
std::string shown_name(const std::string& s) { return textquote::quote_shown(s); }

// The string that starts at `at` in `block`: at most `max` characters, and a NUL behind them inside the block.
bool c_string_at(const uint8_t* block, size_t size, size_t at, size_t max, std::string& out, size_t* end_out = nullptr) {
    if (at >= size) return false;
    size_t e = at;
    while (e < size && block[e] != 0 && e - at <= max) ++e;
    if (e >= size || block[e] != 0 || e - at > max) return false;
    out.assign(reinterpret_cast<const char*>(block + at), e - at);
    if (end_out) *end_out = e;
    return true;
}

}  // namespace

const Property* Node::find_prop(std::string_view n) const {
    for (const Property& p : props)
        if (p.name == n) return &p;
    return nullptr;
}
Property* Node::find_prop(std::string_view n) {
    for (Property& p : props)
        if (p.name == n) return &p;
    return nullptr;
}
const Node* Node::find_child(std::string_view n) const {
    for (const Node& c : children)
        if (c.name == n) return &c;
    return nullptr;
}
Node* Node::find_child(std::string_view n) {
    for (Node& c : children)
        if (c.name == n) return &c;
    return nullptr;
}

bool Node::get_string(std::string_view n, std::string& out) const {
    const Property* p = find_prop(n);
    if (!p || p->value.empty() || p->value.back() != 0) return false;
    for (size_t i = 0; i + 1 < p->value.size(); ++i)
        if (p->value[i] == 0) return false;
    out.assign(reinterpret_cast<const char*>(p->value.data()), p->value.size() - 1);
    return true;
}

bool Node::get_u64(std::string_view n, uint64_t& out) const {
    const Property* p = find_prop(n);
    if (!p || (p->value.size() != 4 && p->value.size() != 8)) return false;
    uint64_t v = 0;
    for (uint8_t b : p->value) v = (v << 8) | b;
    out = v;
    return true;
}

namespace {

// The place of a name in a strings block, found the way libfdt and dtc find one: the first place where the text starts and a NUL
// ends it, so that a name that is the end of a longer one is found inside it. The block of the tree is searched once; the
// names that are added later (at the end) are found by the names that follow.
class StringIndex {
public:
    // `block` has to stay where it is as long as the index lives; it is what the tree has.
    explicit StringIndex(const Bytes& block) {
        const char* base = reinterpret_cast<const char*>(block.data());
        size_t next_nul = block.size();  // the NUL that ends the string at i, found from the back
        std::vector<size_t> nul_at(block.size());
        for (size_t i = block.size(); i-- > 0;) {
            if (block[i] == 0) next_nul = i;
            nul_at[i] = next_nul;
        }
        for (size_t i = 0; i < block.size(); ++i) {
            const size_t e = nul_at[i];
            if (e >= block.size() || e - i > kMaxName) continue;
            first_.emplace(std::string_view(base + i, e - i), static_cast<uint32_t>(i));
        }
        size_ = block.size();
    }

    // Where `name` is, or nullopt.
    bool find(const std::string& name, uint32_t& at) const {
        const auto it = first_.find(std::string_view(name));
        if (it == first_.end()) return false;
        at = it->second;
        return true;
    }

    // `name` goes to the end of the block (which has grown by it: this says by how much the block was before). Every end of it
    // is a name from now on.
    uint32_t add(const std::string& name) {
        const uint32_t at = static_cast<uint32_t>(size_);
        added_.push_back(name);
        const std::string& stored = added_.back();
        for (size_t k = 0; k < stored.size(); ++k) first_.emplace(std::string_view(stored.data() + k, stored.size() - k), static_cast<uint32_t>(at + k));
        size_ += name.size() + 1;
        return at;
    }

private:
    std::unordered_map<std::string_view, uint32_t> first_;
    std::deque<std::string> added_;  // (a deque keeps what the views point into where it is)
    size_t size_ = 0;
};

}  // namespace

Tree parse(const Bytes& data, Layout* layout_out) {
    Layout lay;
    Tree tree;
    if (data.size() < 28) bad("cut short: the header of a blob is at least 28 bytes and there are " + std::to_string(data.size()));
    BinaryReader r(data);
    if (r.be32() != kFdtMagic) bad("this does not start with the bytes d0 0d fe ed");
    const uint64_t total = r.be32();
    const uint64_t off_struct = r.be32();
    const uint64_t off_strings = r.be32();
    const uint64_t off_rsv = r.be32();
    const uint32_t version = r.be32();
    const uint32_t last_comp = r.be32();
    tree.version = version;
    tree.last_comp_version = last_comp;
    if (version < 16) bad("version " + std::to_string(version) + " is older than 16, the oldest that abr reads");
    if (last_comp > 17) bad("last_comp_version " + std::to_string(last_comp) + " is newer than the version 17 that abr reads");
    const size_t header = version >= 17 ? kHeaderV17 : kHeaderV16;
    if (data.size() < header)
        bad("cut short: the header of a version " + std::to_string(version) + " blob is " + std::to_string(header) + " bytes");
    tree.boot_cpuid_phys = r.be32();
    const uint64_t size_strings = r.be32();
    const uint64_t size_struct = version >= 17 ? r.be32() : 0;
    if (total < header || total > data.size())
        bad("the totalsize in the header is " + std::to_string(total) + " bytes, " +
            (total < header ? "less than the header" : "more than the " + std::to_string(data.size()) + " there are"));
    lay.total_size = static_cast<size_t>(total);
    auto not_canonical = [&](const std::string& why) {
        if (lay.canonical) {
            lay.canonical = false;
            lay.why = why;
        }
    };
    if (version < 17) not_canonical("version " + std::to_string(version) + " (abr writes 17)");

    // ---- the memory reservation map
    if (off_rsv < header || off_rsv % 8 != 0 || off_rsv > total)
        bad("the memory reservation map is at offset " + std::to_string(off_rsv) + ", which is not an 8-byte aligned place in the blob");
    size_t rsv_end = 0;
    {
        BinaryReader rr(data.data(), static_cast<size_t>(total));
        rr.seek(static_cast<size_t>(off_rsv));
        for (;;) {
            if (rr.remaining() < 16) bad("the memory reservation map has no end (the blob stops inside it)");
            const uint64_t a = rr.be64();
            const uint64_t s = rr.be64();
            if (a == 0 && s == 0) break;
            if (tree.reserve.size() >= kMaxItems) bad("the memory reservation map has too many entries");
            tree.reserve.emplace_back(a, s);
        }
        rsv_end = rr.pos();
    }

    // ---- the strings block
    if (off_strings > total || size_strings > total - off_strings)
        bad("the strings block (offset " + std::to_string(off_strings) + ", " + std::to_string(size_strings) +
            " bytes) is not inside the blob (" + std::to_string(total) + " bytes)");
    if (size_strings > kMaxStrings)
        bad("the strings block is " + std::to_string(size_strings) + " bytes; abr takes up to " + std::to_string(kMaxStrings));
    tree.strings.assign(data.begin() + static_cast<std::ptrdiff_t>(off_strings),
                        data.begin() + static_cast<std::ptrdiff_t>(off_strings + size_strings));

    // ---- the structure block
    if (off_struct < header || off_struct % 4 != 0 || off_struct > total)
        bad("the structure block is at offset " + std::to_string(off_struct) + ", which is not a 4-byte aligned place in the blob");
    const uint64_t struct_limit = version >= 17 ? off_struct + size_struct : total;
    if (struct_limit > total)
        bad("the structure block (offset " + std::to_string(off_struct) + ", " + std::to_string(size_struct) +
            " bytes) is not inside the blob (" + std::to_string(total) + " bytes)");
    if (version >= 17 && size_struct % 4 != 0)
        bad("the size of the structure block (" + std::to_string(size_struct) + ") is not a multiple of 4");

    std::vector<std::pair<std::string, uint64_t>> name_places;  // the name of every property, and where its nameoff points
    std::vector<Node*> stack;
    std::vector<bool> child_seen;  // per open node: a subnode has been seen (a property behind it cannot be written back)
    size_t items = 0;
    size_t pos = static_cast<size_t>(off_struct);
    const size_t end = static_cast<size_t>(struct_limit);
    bool root_seen = false, root_closed = false, ended = false;
    auto word = [&](size_t at) -> uint32_t {
        return (uint32_t(data[at]) << 24) | (uint32_t(data[at + 1]) << 16) | (uint32_t(data[at + 2]) << 8) | data[at + 3];
    };
    auto pad_zero = [&](size_t from, size_t to) {
        for (size_t i = from; i < to; ++i)
            if (data[i] != 0) {
                not_canonical("padding that is not zero at offset " + std::to_string(i));
                return;
            }
    };
    while (!ended) {
        if (end - pos < 4) bad("the structure block has no END token (it stops at offset " + std::to_string(pos) + ")");
        const uint32_t token = word(pos);
        pos += 4;
        switch (token) {
            case kBeginNode: {
                if (root_closed) bad("a second node at the top level, at offset " + std::to_string(pos - 4));
                std::string name;
                size_t e = 0;
                if (!c_string_at(data.data(), end, pos, kMaxName, name, &e))
                    bad("the name of the node at offset " + std::to_string(pos - 4) + " is not a text that ends in a NUL (at most " +
                        std::to_string(kMaxName) + " characters)");
                const size_t next = static_cast<size_t>(align_up(e + 1, 4));
                if (next > end) bad("the name of the node at offset " + std::to_string(pos - 4) + " runs past the structure block");
                pad_zero(e + 1, next);
                pos = next;
                if (++items > kMaxItems) bad("more than " + std::to_string(kMaxItems) + " nodes and properties");
                if (stack.size() >= kMaxDepth) bad("nodes nested more than " + std::to_string(kMaxDepth) + " deep");
                if (stack.empty()) {
                    if (!name.empty()) bad("the root node has a name (" + shown_name(name) + ")");
                    root_seen = true;
                    stack.push_back(&tree.root);
                } else {
                    Node* parent = stack.back();
                    parent->children.emplace_back();
                    parent->children.back().name = std::move(name);
                    child_seen.back() = true;
                    stack.push_back(&parent->children.back());
                }
                child_seen.push_back(false);
                break;
            }
            case kEndNode:
                if (stack.empty()) bad("an END_NODE token with no node open, at offset " + std::to_string(pos - 4));
                stack.pop_back();
                child_seen.pop_back();
                if (stack.empty()) root_closed = true;
                break;
            case kProp: {
                if (stack.empty()) bad("a property outside any node, at offset " + std::to_string(pos - 4));
                if (end - pos < 8) bad("the property at offset " + std::to_string(pos - 4) + " is cut short");
                const uint64_t len = word(pos);
                const uint64_t nameoff = word(pos + 4);
                pos += 8;
                if (len > end - pos)
                    bad("the value of the property at offset " + std::to_string(pos - 12) + " is " + std::to_string(len) +
                        " bytes, more than the structure block has left");
                std::string name;
                if (!c_string_at(tree.strings.data(), tree.strings.size(), static_cast<size_t>(nameoff), kMaxName, name))
                    bad("the name of the property at offset " + std::to_string(pos - 12) + " (strings block offset " + std::to_string(nameoff) +
                        ") is not a text that ends in a NUL inside the strings block (at most " + std::to_string(kMaxName) + " characters)");
                if (++items > kMaxItems) bad("more than " + std::to_string(kMaxItems) + " nodes and properties");
                const size_t vlen = static_cast<size_t>(len);
                const size_t next = static_cast<size_t>(align_up(pos + vlen, 4));
                if (next > end) bad("the value of the property at offset " + std::to_string(pos - 12) + " runs past the structure block");
                name_places.emplace_back(name, nameoff);
                Property p;
                p.name = std::move(name);
                p.value.assign(data.begin() + static_cast<std::ptrdiff_t>(pos), data.begin() + static_cast<std::ptrdiff_t>(pos + vlen));
                pad_zero(pos + vlen, next);
                pos = next;
                if (child_seen.back()) not_canonical("a property comes after a subnode (a node's properties are written before its subnodes)");
                stack.back()->props.push_back(std::move(p));
                break;
            }
            case kNop:
                not_canonical("a NOP token at offset " + std::to_string(pos - 4));
                break;
            case kEnd:
                ended = true;
                break;
            default:
                bad("the structure block has the token " + hex32(token) + " at offset " + std::to_string(pos - 4) + ", which is none");
        }
    }
    if (!stack.empty()) bad("the structure block ends with " + std::to_string(stack.size()) + " node(s) still open");
    if (!root_seen) bad("the structure block has no node");
    const size_t struct_used = pos - static_cast<size_t>(off_struct);
    if (version >= 17 && struct_used != size_struct)
        not_canonical("the structure block is " + std::to_string(size_struct) + " bytes and its END token is at " + std::to_string(struct_used));

    // ---- how the blocks lie
    {
        struct Block {
            const char* what;
            uint64_t from, to;
        };
        const Block blocks[] = {
            {"the memory reservation map", off_rsv, rsv_end},
            {"the structure block", off_struct, off_struct + (version >= 17 ? size_struct : struct_used)},
            {"the strings block", off_strings, off_strings + size_strings},
        };
        for (size_t i = 0; i < 3; ++i)
            for (size_t j = i + 1; j < 3; ++j)
                if (blocks[i].from < blocks[j].to && blocks[j].from < blocks[i].to)
                    bad(std::string(blocks[i].what) + " and " + blocks[j].what + " overlap");
    }
    if (off_rsv != kHeaderV17 || off_struct != kHeaderV17 + 16 * (tree.reserve.size() + 1) || off_strings != off_struct + struct_used)
        not_canonical("the blocks are not the header, the reservation map, the structure block and the strings block one behind the other");
    if (lay.canonical) {  // (build() puts a name where libfdt would find it: the first place its text is)
        const StringIndex index(tree.strings);
        for (const auto& [name, at] : name_places) {
            uint32_t first = 0;
            if (!index.find(name, first) || first != at) {
                not_canonical("the name " + shown_name(name) + " of a property is not at the first place its text has in the strings block");
                break;
            }
        }
    }
    lay.used = static_cast<size_t>(off_strings + size_strings);
    {
        bool zero = true;
        for (size_t i = lay.used; i < lay.total_size && zero; ++i) zero = data[i] == 0;
        if (zero) lay.slack = lay.total_size - lay.used;
        else not_canonical("bytes that are not zero behind the strings block");
    }
    if (layout_out) *layout_out = lay;
    return tree;
}

uint32_t string_offset(Bytes& strings, const std::string& name) {
    StringIndex idx(strings);
    uint32_t at = 0;
    if (idx.find(name, at)) return at;
    at = static_cast<uint32_t>(strings.size());
    strings.insert(strings.end(), name.begin(), name.end());
    strings.push_back(0);
    return at;
}

Bytes build(const Tree& tree, size_t slack) {
    if (tree.version < 17) throw FormatError("flattened device tree: abr writes version 17, and this tree is version " + std::to_string(tree.version));
    if (!tree.root.name.empty()) throw FormatError("flattened device tree: the root node has a name");
    Bytes strings = tree.strings;
    StringIndex index(tree.strings);
    auto name_offset = [&](const std::string& name) -> uint32_t {
        if (name.size() > kMaxName)
            throw FormatError("flattened device tree: the property name " + shown_name(name.substr(0, 40)) + "... is longer than " + std::to_string(kMaxName));
        if (name.find('\0') != std::string::npos) throw FormatError("flattened device tree: a property name has a NUL in it");
        uint32_t at = 0;
        if (index.find(name, at)) return at;
        at = index.add(name);
        strings.insert(strings.end(), name.begin(), name.end());
        strings.push_back(0);
        return at;
    };

    BinaryWriter st;
    struct Frame {
        const Node* node;
        size_t next_prop, next_child;
    };
    std::vector<Frame> stack;
    size_t items = 0;
    auto open = [&](const Node& n) {
        if (stack.size() >= kMaxDepth) throw FormatError("flattened device tree: nodes nested more than " + std::to_string(kMaxDepth) + " deep");
        if (n.name.size() > kMaxName || n.name.find('\0') != std::string::npos)
            throw FormatError("flattened device tree: the node name " + shown_name(n.name.substr(0, 40)) + " is not a name");
        if (++items > kMaxItems) throw FormatError("flattened device tree: more than " + std::to_string(kMaxItems) + " nodes and properties");
        st.be32(kBeginNode);
        st.bytes(reinterpret_cast<const uint8_t*>(n.name.data()), n.name.size());
        st.u8(0);
        st.align(4);
        stack.push_back({&n, 0, 0});
    };
    open(tree.root);
    while (!stack.empty()) {
        Frame& f = stack.back();
        if (f.next_prop < f.node->props.size()) {
            const Property& p = f.node->props[f.next_prop++];
            if (!p.incbin.empty())
                throw FormatError("flattened device tree: the property " + shown_name(p.name) + " still names a file (" + shown_name(p.incbin) + ")");
            if (++items > kMaxItems) throw FormatError("flattened device tree: more than " + std::to_string(kMaxItems) + " nodes and properties");
            if (p.value.size() > 0xFFFFFFFFull) throw FormatError("flattened device tree: the value of " + shown_name(p.name) + " is 4 GiB or more");
            st.be32(kProp);
            st.be32(static_cast<uint32_t>(p.value.size()));
            st.be32(name_offset(p.name));
            st.bytes(p.value);
            st.align(4);
        } else if (f.next_child < f.node->children.size()) {
            const Node& c = f.node->children[f.next_child++];
            open(c);  // (`f` is not used again)
        } else {
            st.be32(kEndNode);
            stack.pop_back();
        }
    }
    st.be32(kEnd);

    const uint64_t rsv_size = 16 * (static_cast<uint64_t>(tree.reserve.size()) + 1);
    const uint64_t off_struct = kHeaderV17 + rsv_size;
    const uint64_t off_strings = off_struct + st.size();
    const uint64_t total = off_strings + strings.size() + slack;
    if (total >= 0x100000000ull) throw FormatError("flattened device tree: the blob would be 4 GiB or more");
    BinaryWriter w;
    w.be32(kFdtMagic);
    w.be32(static_cast<uint32_t>(total));
    w.be32(static_cast<uint32_t>(off_struct));
    w.be32(static_cast<uint32_t>(off_strings));
    w.be32(static_cast<uint32_t>(kHeaderV17));
    w.be32(tree.version);
    w.be32(tree.last_comp_version);
    w.be32(tree.boot_cpuid_phys);
    w.be32(static_cast<uint32_t>(strings.size()));
    w.be32(static_cast<uint32_t>(st.size()));
    for (const auto& [a, s] : tree.reserve) {
        w.be64(a);
        w.be64(s);
    }
    w.be64(0);
    w.be64(0);
    w.bytes(st.data());
    w.bytes(strings);
    w.zeros(slack);
    return w.take();
}

}  // namespace abr::fdt
