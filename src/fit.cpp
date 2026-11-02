// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/fit.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <numeric>

#include <zlib.h>

#include "abr/dtb.hpp"
#include "abr/dts.hpp"
#include "abr/sha.hpp"
#include "abr/textquote.hpp"

namespace abr::fit {

namespace {

constexpr size_t kMaxAlign = 1u << 20;  // the biggest alignment that open() takes from a file

std::string shown(std::string_view s) { return textquote::quote_shown(s); }

uint64_t align_up(uint64_t v, uint64_t a) { return (v + a - 1) / a * a; }

bool is_power_of_two(size_t v) { return v != 0 && (v & (v - 1)) == 0; }

// A property that is one 32-bit cell.
bool cell_of(const fdt::Property* p, uint32_t& out) {
    if (!p || p->value.size() != 4) return false;
    out = (uint32_t(p->value[0]) << 24) | (uint32_t(p->value[1]) << 16) | (uint32_t(p->value[2]) << 8) | uint32_t(p->value[3]);
    return true;
}

Bytes cell_bytes(uint32_t v) { return {uint8_t(v >> 24), uint8_t(v >> 16), uint8_t(v >> 8), uint8_t(v)}; }

// The property gets the number where it is; a property that is not there is put first in its node, which is where libfdt (and
// so mkimage) puts a new one.
void set_cell(fdt::Node& n, const std::string& name, uint32_t v) {
    if (fdt::Property* p = n.find_prop(name)) {
        p->value = cell_bytes(v);
        p->incbin.clear();
        return;
    }
    n.props.insert(n.props.begin(), fdt::Property{name, cell_bytes(v), std::string()});
}

void erase_prop(fdt::Node& n, std::string_view name) {
    n.props.erase(std::remove_if(n.props.begin(), n.props.end(), [&](const fdt::Property& p) { return p.name == name; }), n.props.end());
}

// A property that is a list of strings: every one of printable characters, the last with its NUL. (Empty for any other.)
std::vector<std::string> strings_of(const fdt::Property& p) {
    std::vector<std::string> out;
    if (p.value.empty() || p.value.back() != 0) return out;
    size_t at = 0;
    while (at < p.value.size()) {
        size_t end = at;
        while (p.value[end] != 0) {
            if (p.value[end] < 0x20 || p.value[end] >= 0x7f) return {};
            ++end;
        }
        out.emplace_back(reinterpret_cast<const char*>(p.value.data()) + at, end - at);
        at = end + 1;
    }
    return out;
}

bool starts_with(const std::string& s, std::string_view prefix) { return s.compare(0, prefix.size(), prefix) == 0; }

std::string hex_text(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

size_t first_difference(const Bytes& a, const uint8_t* b, size_t n) {
    const size_t m = std::min(a.size(), n);
    for (size_t i = 0; i < m; ++i)
        if (a[i] != b[i]) return i;
    return m;
}

}  // namespace

const char* place_name(Place p) {
    switch (p) {
        case Place::INLINE: return "inline";
        case Place::OFFSET: return "offset";
        case Place::POSITION: return "position";
    }
    return "inline";
}

std::optional<Place> place_from_name(std::string_view name) {
    if (name == "inline") return Place::INLINE;
    if (name == "offset") return Place::OFFSET;
    if (name == "position") return Place::POSITION;
    return std::nullopt;
}

bool looks_like(const Bytes& file) {
    if (file.size() < 40 || file[0] != 0xd0 || file[1] != 0x0d || file[2] != 0xfe || file[3] != 0xed) return false;
    try {
        const fdt::Tree tree = fdt::parse(file);
        const fdt::Node* images = tree.root.find_child("images");
        return images && !images->children.empty();
    } catch (const FormatError&) {
        return false;
    }
}

// ------------------------------------------------------------------- build --

// The zero bytes behind the strings of the tree: those the layout has, or those that make the tree end at a multiple of its alignment.
size_t slack_of(const fdt::Tree& tree, const Layout& layout) {
    if (layout.tree_align <= 1) return layout.slack;
    const uint64_t used = fdt::build(tree, 0).size();
    return static_cast<size_t>(align_up(used, layout.tree_align) - used);
}

Bytes build(fdt::Tree tree, const Layout& layout) {
    if (layout.place == Place::INLINE) return fdt::build(tree, layout.slack);
    if (layout.align < 4 || !is_power_of_two(layout.align))
        throw FormatError("the alignment of the images (fit_align) is " + std::to_string(layout.align) + ", not a power of two of at least 4");
    if (!is_power_of_two(layout.end_align))
        throw FormatError("the alignment of the end of the file (fit_end_align) is " + std::to_string(layout.end_align) + ", not a power of two");
    if (layout.tree_align > 1 && !is_power_of_two(layout.tree_align))
        throw FormatError("the alignment of the end of the tree (fit_tree_align) is " + std::to_string(layout.tree_align) + ", not a power of two");

    fdt::Node* images = tree.root.find_child("images");
    if (!images) throw FormatError("the FIT has no /images node");
    const char* start_name = layout.place == Place::OFFSET ? "data-offset" : "data-position";
    const char* other_name = layout.place == Place::OFFSET ? "data-position" : "data-offset";

    // What goes behind the tree: the images that have a `data`. It leaves the tree; data-size and data-offset (data-position)
    // take its place.
    struct Item {
        fdt::Node* node;
        Bytes data;
        bool has_start = false;  // the node had the property the place asks for, with a number
        bool recorded = false;   // ... and a data-size that is the size of the data: the image has not changed size
        uint64_t start = 0;
    };
    std::vector<Item> items;
    for (fdt::Node& n : images->children) {
        fdt::Property* d = n.find_prop("data");
        if (!d) continue;
        if (!d->incbin.empty())
            throw FormatError("the image " + shown(n.name) + " has data = /incbin/(" + shown(d->incbin) + ") that has not been read");
        Item it;
        it.node = &n;
        it.data = std::move(d->value);
        erase_prop(n, "data");
        if (it.data.size() > UINT32_MAX)
            throw FormatError("the image " + shown(n.name) + " is " + std::to_string(it.data.size()) + " bytes; data-size is a 32-bit number");
        uint32_t old_size = 0, old_start = 0;
        const bool size_ok = cell_of(n.find_prop("data-size"), old_size) && old_size == it.data.size();
        it.has_start = cell_of(n.find_prop(start_name), old_start);
        it.start = old_start;
        it.recorded = size_ok && it.has_start;
        items.push_back(std::move(it));
    }
    if (items.empty()) return fdt::build(tree, slack_of(tree, layout));

    // The properties first with numbers that give the tree its size (they are all one cell, so the size does not depend on them).
    for (Item& it : items) {
        set_cell(*it.node, start_name, static_cast<uint32_t>(it.has_start ? it.start : 0));
        set_cell(*it.node, "data-size", static_cast<uint32_t>(it.data.size()));
        erase_prop(*it.node, other_name);
    }
    const size_t slack = slack_of(tree, layout);
    const uint64_t tree_size = fdt::build(tree, slack).size();
    const uint64_t base = layout.place == Place::OFFSET ? align_up(tree_size, 4) : 0;  // what the offsets count from

    // Where the images go: where the properties said, when every image is the size it was; otherwise one behind the other.
    bool recorded = true;
    for (const Item& it : items) recorded = recorded && it.recorded;
    std::vector<size_t> order(items.size());
    std::iota(order.begin(), order.end(), size_t{0});
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        const uint64_t ka = items[a].has_start ? items[a].start : UINT64_MAX;
        const uint64_t kb = items[b].has_start ? items[b].start : UINT64_MAX;
        return ka < kb;
    });
    std::vector<uint64_t> start(items.size(), 0);
    if (recorded) {
        for (size_t i = 0; i < items.size(); ++i) start[i] = items[i].start;
    } else {
        bool any_old = false;
        uint64_t smallest = UINT64_MAX;
        for (const Item& it : items)
            if (it.has_start) {
                any_old = true;
                smallest = std::min(smallest, it.start);
            }
        // (the first of the images that had a place keeps it; with none that had, the first goes right behind the tree)
        const uint64_t first = any_old ? smallest : (layout.place == Place::OFFSET ? 0 : align_up(tree_size, layout.align));
        uint64_t at = first;
        bool is_first = true;
        for (size_t k : order) {
            const uint64_t s = is_first ? first : align_up(at, layout.align);
            is_first = false;
            start[k] = s;
            at = s + items[k].data.size();
        }
    }
    for (size_t k = 0; k < items.size(); ++k)
        if (start[k] > UINT32_MAX)
            throw FormatError("the image " + shown(items[k].node->name) + " would be at " + std::to_string(start[k]) + ", which is not a 32-bit number");

    std::vector<size_t> by_start = order;
    std::stable_sort(by_start.begin(), by_start.end(), [&](size_t a, size_t b) { return start[a] < start[b]; });
    for (size_t j = 0; j < by_start.size(); ++j) {
        const size_t k = by_start[j];
        const uint64_t at = base + start[k];
        if (j == 0 && at < tree_size)
            throw FormatError("the tree of the FIT is " + std::to_string(tree_size) + " bytes, which reaches the image " + shown(items[k].node->name) +
                              " at " + start_name + " " + std::to_string(start[k]) +
                              ": make the tree smaller, or move the images (" + start_name + " in fit.its)");
        if (j > 0) {
            const size_t p = by_start[j - 1];
            if (at < base + start[p] + items[p].data.size())
                throw FormatError("the images " + shown(items[p].node->name) + " and " + shown(items[k].node->name) + " overlap (" + start_name + " " +
                                  std::to_string(start[p]) + " and " + std::to_string(start[k]) + ", the first is " + std::to_string(items[p].data.size()) +
                                  " bytes)");
        }
    }
    for (size_t k = 0; k < items.size(); ++k) set_cell(*items[k].node, start_name, static_cast<uint32_t>(start[k]));

    Bytes out = fdt::build(tree, slack);
    if (out.size() != tree_size) throw FormatError("the tree of the FIT changed its size while the images were placed");
    out.resize(static_cast<size_t>(std::max<uint64_t>(base, out.size())), 0);
    for (size_t k : by_start) {
        const uint64_t at = base + start[k];
        if (at > out.size()) out.resize(static_cast<size_t>(at), 0);
        out.insert(out.end(), items[k].data.begin(), items[k].data.end());
        Bytes().swap(items[k].data);
    }
    if (layout.end_align > 1) out.resize(static_cast<size_t>(align_up(out.size(), layout.end_align)), 0);
    return out;
}

// -------------------------------------------------------------------- open --

std::optional<Opened> open(const Bytes& file, std::string& why) {
    Opened o;
    fdt::Layout fl;
    try {
        o.tree = fdt::parse(file, &fl);
    } catch (const FormatError& e) {
        why = e.what();
        return std::nullopt;
    }
    if (!fl.canonical) {
        why = "its tree is not laid out the way dtc and libfdt write one (" + fl.why + ")";
        return std::nullopt;
    }
    fdt::Node* images = o.tree.root.find_child("images");
    if (!images) {
        why = "it has no /images node";
        return std::nullopt;
    }
    o.layout.slack = fl.slack;
    const uint64_t tree_end = fl.total_size;  // the end of the blob, what the images come behind

    struct External {
        size_t index;
        uint64_t start;  // as the node says (an offset or a position)
        uint32_t size;
    };
    std::vector<External> external;
    std::vector<size_t> inline_images;
    size_t offsets = 0, positions = 0;
    std::set<std::string> names;
    for (size_t i = 0; i < images->children.size(); ++i) {
        const fdt::Node& n = images->children[i];
        if (!names.insert(n.name).second) {
            why = "two images are called " + shown(n.name);
            return std::nullopt;
        }
        const fdt::Property* data = n.find_prop("data");
        const fdt::Property* size = n.find_prop("data-size");
        const fdt::Property* off = n.find_prop("data-offset");
        const fdt::Property* pos = n.find_prop("data-position");
        const std::string label = "the image " + shown(n.name);
        if (data && (size || off || pos)) {
            why = label + " has `data` and also data-size, data-offset or data-position";
            return std::nullopt;
        }
        if (data) {
            inline_images.push_back(i);
            continue;
        }
        if (!size && !off && !pos) continue;  // an image without data
        uint32_t sz = 0, st = 0;
        if (!size || (!off && !pos) || (off && pos) || !cell_of(size, sz) || !cell_of(off ? off : pos, st)) {
            why = label + " has data-size, data-offset and data-position that are not what an image behind the tree has (a data-size, and a data-offset or a "
                          "data-position, each one 32-bit number)";
            return std::nullopt;
        }
        (off ? offsets : positions)++;
        external.push_back({i, st, sz});
    }
    if (!inline_images.empty() && !external.empty()) {
        why = "some images have their data in the tree and some behind it";
        return std::nullopt;
    }
    if (offsets && positions) {
        why = "some images have a data-offset and some a data-position";
        return std::nullopt;
    }
    o.layout.place = offsets ? Place::OFFSET : positions ? Place::POSITION : Place::INLINE;

    // The data of the images.
    for (size_t i : inline_images) {
        fdt::Node& n = images->children[i];
        fdt::Property* d = n.find_prop("data");
        if (!d->pad.empty()) {
            why = "the bytes behind the data of the image " + shown(n.name) + ", up to a multiple of 4, are not zero";
            return std::nullopt;
        }
        Image im;
        im.index = i;
        im.name = n.name;
        n.get_string("type", im.type);
        im.data = std::move(d->value);
        d->value.clear();
        o.images.push_back(std::move(im));
    }
    uint64_t last_end = tree_end;
    if (!external.empty()) {
        const uint64_t base = o.layout.place == Place::OFFSET ? align_up(tree_end, 4) : 0;
        std::vector<size_t> order(external.size());
        std::iota(order.begin(), order.end(), size_t{0});
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return external[a].start < external[b].start; });
        uint64_t at = tree_end;  // everything before this is accounted for: the tree, the images before this one, their padding
        for (size_t k : order) {
            const External& e = external[k];
            fdt::Node& n = images->children[e.index];
            const std::string label = "the image " + shown(n.name);
            const uint64_t start = base + e.start;
            const uint64_t end = start + e.size;
            if (end > file.size()) {
                why = label + " ends at " + std::to_string(end) + ", behind the end of the file (" + std::to_string(file.size()) + " bytes)";
                return std::nullopt;
            }
            if (start < at) {
                why = label + " starts at " + std::to_string(start) + ", where the tree or another image is";
                return std::nullopt;
            }
            for (uint64_t b = at; b < start; ++b)
                if (file[static_cast<size_t>(b)] != 0) {
                    why = "bytes that are not zero (at " + std::to_string(b) + ") between the tree or an image and " + label;
                    return std::nullopt;
                }
            Image im;
            im.index = e.index;
            im.name = n.name;
            n.get_string("type", im.type);
            im.data.assign(file.begin() + static_cast<std::ptrdiff_t>(start), file.begin() + static_cast<std::ptrdiff_t>(end));
            o.images.push_back(std::move(im));
            // `data`, where the node says that it has data (the properties are not touched: they are what the layout is made of)
            size_t where = 0;
            while (where < n.props.size() && n.props[where].name != "data-size" && n.props[where].name != "data-offset" &&
                   n.props[where].name != "data-position")
                ++where;
            n.props.insert(n.props.begin() + static_cast<std::ptrdiff_t>(where), fdt::Property{"data", Bytes(), std::string()});
            at = end;
            last_end = end;
        }
        // What the images are aligned to: the biggest power of two that all their (non-zero) places are a multiple of.
        size_t align = 4;
        for (size_t candidate = 8; candidate <= kMaxAlign; candidate <<= 1) {
            bool any = false, all = true;
            for (const External& e : external)
                if (e.start != 0) {
                    any = true;
                    if (e.start % candidate != 0) all = false;
                }
            if (!any || !all) break;
            align = candidate;
        }
        o.layout.align = align;
        const uint64_t padded = align_up(last_end, align);
        bool zeros = padded <= file.size();
        for (uint64_t b = last_end; zeros && b < padded; ++b) zeros = file[static_cast<size_t>(b)] == 0;
        o.layout.end_align = zeros ? align : 1;
        // How the end of the tree is padded: up to a multiple of what mkimage was given for -B (the smallest power of two that makes
        // the blob end where it does), or by some number of bytes that no alignment says.
        for (size_t t = 4; t <= kMaxAlign; t <<= 1)
            if (align_up(fl.used, t) == fl.total_size) {
                o.layout.tree_align = t;
                break;
            }
        o.consumed = static_cast<size_t>(zeros ? padded : last_end);
    } else {
        o.consumed = static_cast<size_t>(tree_end);
    }
    std::sort(o.images.begin(), o.images.end(), [](const Image& a, const Image& b) { return a.index < b.index; });

    // Does it come back? The tree as text and from the text, the images in it, the layout: what a repack of the unpacked files
    // does, in memory.
    try {
        fdt::Tree named = o.tree;
        fdt::Node* named_images = named.root.find_child("images");
        for (const Image& im : o.images)
            if (!im.data.empty()) named_images->children[im.index].find_prop("data")->incbin = "x";
        fdt::Tree back = dts::parse(dts::print(named), "the text of the tree");
        back.version = o.tree.version;
        back.last_comp_version = o.tree.last_comp_version;
        back.boot_cpuid_phys = o.tree.boot_cpuid_phys;
        back.strings = o.tree.strings;
        fdt::Node* back_images = back.root.find_child("images");
        if (!back_images || back_images->children.size() != images->children.size()) {
            why = "its tree does not come back from the text it is written as";
            return std::nullopt;
        }
        for (const Image& im : o.images) {
            fdt::Property* p = back_images->children[im.index].find_prop("data");
            if (!p) {
                why = "the data of the image " + shown(im.name) + " does not come back from the text it is written as";
                return std::nullopt;
            }
            p->value = im.data;
            p->incbin.clear();
        }
        const Bytes again = build(std::move(back), o.layout);
        if (again.size() != o.consumed) {
            why = "it would come back as " + std::to_string(again.size()) + " bytes, not " + std::to_string(o.consumed);
            return std::nullopt;
        }
        if (std::memcmp(again.data(), file.data(), again.size()) != 0) {
            why = "it would not come back byte for byte (the first difference is at " + std::to_string(first_difference(again, file.data(), again.size())) + ")";
            return std::nullopt;
        }
    } catch (const FormatError& e) {
        why = std::string("it would not come back: ") + e.what();
        return std::nullopt;
    }
    return o;
}

// ------------------------------------------------------------------ hashes --

std::optional<Bytes> hash_value(std::string_view algo, const Bytes& data) {
    if (algo == "crc32") {
        uLong crc = crc32(0L, Z_NULL, 0);
        size_t at = 0;
        while (at < data.size()) {
            const size_t n = std::min<size_t>(data.size() - at, size_t{1} << 30);
            crc = crc32(crc, data.data() + at, static_cast<uInt>(n));
            at += n;
        }
        return cell_bytes(static_cast<uint32_t>(crc));
    }
    if (algo == "md5") return hash::md5(data);
    if (algo == "sha1") return hash::sha1(data);
    if (algo == "sha256") return hash::sha256(data);
    if (algo == "sha384") return hash::sha384(data);
    if (algo == "sha512") return hash::sha512(data);
    return std::nullopt;
}

size_t refresh_hashes(fdt::Tree& tree, const std::vector<size_t>& which, std::vector<std::string>& notes) {
    fdt::Node* images = tree.root.find_child("images");
    if (!images) return 0;
    size_t count = 0;
    for (size_t index : which) {
        if (index >= images->children.size()) continue;
        fdt::Node& image = images->children[index];
        const fdt::Property* data = image.find_prop("data");
        if (!data || !data->incbin.empty()) continue;
        for (fdt::Node& h : image.children) {
            if (!starts_with(h.name, "hash")) continue;
            const std::string where = "/images/" + image.name + "/" + h.name;
            std::string algo;
            if (!h.get_string("algo", algo)) {
                notes.push_back(shown(where) + " has no algo: its value is left as it is");
                continue;
            }
            const std::optional<Bytes> value = hash_value(algo, data->value);
            if (!value) {
                notes.push_back(shown(where) + " is a hash of the algorithm " + shown(algo) + ", which abr does not know: its value is left as it is");
                continue;
            }
            if (fdt::Property* p = h.find_prop("value")) {
                p->value = *value;
                p->incbin.clear();
            } else {
                h.props.insert(h.props.begin(), fdt::Property{"value", *value, std::string()});
            }
            ++count;
        }
    }
    return count;
}

std::vector<std::string> wrong_hashes(const fdt::Tree& tree, const std::vector<Image>& images) {
    std::vector<std::string> out;
    const fdt::Node* group = tree.root.find_child("images");
    if (!group) return out;
    for (const Image& im : images) {
        if (im.index >= group->children.size()) continue;
        const fdt::Node& node = group->children[im.index];
        for (const fdt::Node& h : node.children) {
            if (!starts_with(h.name, "hash")) continue;
            std::string algo;
            const fdt::Property* value = h.find_prop("value");
            if (!h.get_string("algo", algo) || !value) continue;
            const std::optional<Bytes> digest = hash_value(algo, im.data);
            if (digest && *digest != value->value)
                out.push_back("the " + shown(algo) + " hash /images/" + node.name + "/" + h.name + " is not the hash of the data of the image");
        }
    }
    return out;
}

// -------------------------------------------------------------- signatures --

std::vector<std::string> signatures(const fdt::Tree& tree) {
    std::vector<std::string> out;
    for (const char* group : {"images", "configurations"}) {
        const fdt::Node* g = tree.root.find_child(group);
        if (!g) continue;
        for (const fdt::Node& n : g->children)
            for (const fdt::Node& s : n.children)
                if (starts_with(s.name, "signature")) out.push_back(std::string("/") + group + "/" + n.name + "/" + s.name);
    }
    return out;
}

std::vector<std::string> stale_signatures(const fdt::Tree& tree, const std::set<std::string>& changed) {
    std::vector<std::string> out;
    if (changed.empty()) return out;
    if (const fdt::Node* images = tree.root.find_child("images")) {
        for (const fdt::Node& n : images->children) {
            if (!changed.count(n.name)) continue;
            for (const fdt::Node& s : n.children)
                if (starts_with(s.name, "signature")) out.push_back("/images/" + n.name + "/" + s.name);
        }
    }
    if (const fdt::Node* configs = tree.root.find_child("configurations")) {
        for (const fdt::Node& c : configs->children) {
            bool covers = false;
            for (const fdt::Property& p : c.props) {
                if (p.name == "description") continue;
                for (const std::string& s : strings_of(p))
                    if (changed.count(s)) covers = true;
            }
            if (!covers) continue;
            for (const fdt::Node& s : c.children)
                if (starts_with(s.name, "signature")) out.push_back("/configurations/" + c.name + "/" + s.name);
        }
    }
    return out;
}

// -------------------------------------------------------------------- info --

std::string describe_image(const fdt::Node& n) {
    std::string out;
    auto add = [&](const std::string& s) {
        if (!out.empty()) out += ", ";
        out += s;
    };
    std::string text;
    if (n.get_string("type", text)) add("type " + shown(text));
    if (n.get_string("arch", text)) add("arch " + shown(text));
    if (n.get_string("os", text)) add("os " + shown(text));
    if (n.get_string("compression", text)) add("compression " + shown(text));
    uint64_t v = 0;
    if (n.get_u64("load", v)) add("load " + hex_text(v));
    if (n.get_u64("entry", v)) add("entry " + hex_text(v));
    std::string algos;
    size_t signatures_here = 0;
    for (const fdt::Node& c : n.children) {
        if (starts_with(c.name, "hash") && c.get_string("algo", text)) algos += (algos.empty() ? "" : "+") + text;
        if (starts_with(c.name, "signature")) ++signatures_here;
    }
    if (!algos.empty()) add("hash " + shown(algos));
    if (signatures_here) add(std::to_string(signatures_here) + (signatures_here == 1 ? " signature" : " signatures"));
    return out;
}

std::vector<std::string> describe_configurations(const fdt::Tree& tree) {
    std::vector<std::string> out;
    const fdt::Node* configs = tree.root.find_child("configurations");
    if (!configs) return out;
    std::string chosen;
    configs->get_string("default", chosen);
    for (const fdt::Node& c : configs->children) {
        std::string line = shown(c.name) + (c.name == chosen ? " (the default)" : "") + ":";
        for (const fdt::Property& p : c.props) {
            if (p.name == "description") continue;
            const std::vector<std::string> list = strings_of(p);
            if (list.empty()) continue;
            std::string joined;
            for (const std::string& s : list) joined += (joined.empty() ? "" : ", ") + s;
            line += " " + shown(p.name) + "=" + shown(joined);
        }
        size_t signed_here = 0;
        for (const fdt::Node& s : c.children)
            if (starts_with(s.name, "signature")) ++signed_here;
        if (signed_here) line += " (signed)";
        out.push_back(std::move(line));
    }
    return out;
}

}  // namespace abr::fit
