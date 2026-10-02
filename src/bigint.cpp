// SPDX-License-Identifier: GPL-3.0-or-later
#include "abr/bigint.hpp"

#include <algorithm>

namespace abr {

namespace {

unsigned clz32(uint32_t x) {
    unsigned n = 0;
    if (x == 0) return 32;
    while (!(x & 0x80000000u)) {
        x <<= 1;
        ++n;
    }
    return n;
}

// Montgomery arithmetic modulo an odd n of k limbs, R = 2^(32k).
class Montgomery {
public:
    explicit Montgomery(const std::vector<uint32_t>& n) : n_(n), k_(n.size()) {
        n0inv_ = neg_inverse_mod32(n_[0]);
    }

    size_t k() const { return k_; }

    // out = a * b * R^-1 mod n; a, b, out are k limbs, a and b < n.
    void mul(const uint32_t* a, const uint32_t* b, uint32_t* out) const {
        std::vector<uint32_t> t(k_ + 2, 0);
        for (size_t i = 0; i < k_; ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < k_; ++j) {
                uint64_t cur = static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(a[j]) * b[i] + carry;
                t[j] = static_cast<uint32_t>(cur);
                carry = cur >> 32;
            }
            uint64_t top = static_cast<uint64_t>(t[k_]) + carry;
            t[k_] = static_cast<uint32_t>(top);
            t[k_ + 1] = static_cast<uint32_t>(top >> 32);

            uint32_t m = t[0] * n0inv_;
            carry = (static_cast<uint64_t>(t[0]) + static_cast<uint64_t>(m) * n_[0]) >> 32;
            for (size_t j = 1; j < k_; ++j) {
                uint64_t cur = static_cast<uint64_t>(t[j]) + static_cast<uint64_t>(m) * n_[j] + carry;
                t[j - 1] = static_cast<uint32_t>(cur);
                carry = cur >> 32;
            }
            uint64_t cur = static_cast<uint64_t>(t[k_]) + carry;
            t[k_ - 1] = static_cast<uint32_t>(cur);
            t[k_] = t[k_ + 1] + static_cast<uint32_t>(cur >> 32);
        }
        // Result is t[0..k] and is < 2n: one conditional subtraction.
        bool ge = t[k_] != 0;
        if (!ge) {
            ge = true;
            for (size_t i = k_; i-- > 0;) {
                if (t[i] != n_[i]) {
                    ge = t[i] > n_[i];
                    break;
                }
            }
        }
        if (ge) {
            int64_t borrow = 0;
            for (size_t i = 0; i < k_; ++i) {
                int64_t cur = static_cast<int64_t>(t[i]) - static_cast<int64_t>(n_[i]) - borrow;
                borrow = cur < 0 ? 1 : 0;
                t[i] = static_cast<uint32_t>(cur);
            }
        }
        std::copy(t.begin(), t.begin() + static_cast<long>(k_), out);
    }

private:
    std::vector<uint32_t> n_;
    size_t k_;
    uint32_t n0inv_;
};

}  // namespace

// Newton iteration: each step doubles the number of correct low bits,
// starting from 3 correct bits for any odd n (n*n == 1 mod 8).
uint32_t neg_inverse_mod32(uint32_t n) {
    uint32_t x = n;
    for (int i = 0; i < 5; ++i) x *= 2u - n * x;
    return 0u - x;
}

BigInt::BigInt(uint64_t v) {
    while (v) {
        d_.push_back(static_cast<uint32_t>(v));
        v >>= 32;
    }
}

void BigInt::trim() {
    while (!d_.empty() && d_.back() == 0) d_.pop_back();
}

BigInt BigInt::from_bytes_be(const uint8_t* p, size_t n) {
    BigInt r;
    r.d_.assign((n + 3) / 4, 0);
    for (size_t i = 0; i < n; ++i) {
        size_t from_end = n - 1 - i;  // byte index counted from the least significant end
        r.d_[from_end / 4] |= static_cast<uint32_t>(p[i]) << (8 * (from_end % 4));
    }
    r.trim();
    return r;
}

Bytes BigInt::to_bytes_be(size_t width) const {
    size_t need = (bit_length() + 7) / 8;
    if (need == 0) need = 1;
    if (width == 0) width = need;
    if (need > width && !(is_zero() && width > 0))
        throw FormatError("number needs " + std::to_string(need) + " bytes, only " +
                          std::to_string(width) + " available");
    Bytes out(width, 0);
    for (size_t i = 0; i < d_.size() * 4 && i < width; ++i)
        out[width - 1 - i] = static_cast<uint8_t>(d_[i / 4] >> (8 * (i % 4)));
    return out;
}

size_t BigInt::bit_length() const {
    if (d_.empty()) return 0;
    return d_.size() * 32 - clz32(d_.back());
}

bool BigInt::bit(size_t index) const {
    size_t limb = index / 32;
    if (limb >= d_.size()) return false;
    return (d_[limb] >> (index % 32)) & 1u;
}

int BigInt::compare(const BigInt& a, const BigInt& b) {
    if (a.d_.size() != b.d_.size()) return a.d_.size() < b.d_.size() ? -1 : 1;
    for (size_t i = a.d_.size(); i-- > 0;)
        if (a.d_[i] != b.d_[i]) return a.d_[i] < b.d_[i] ? -1 : 1;
    return 0;
}

BigInt BigInt::add(const BigInt& a, const BigInt& b) {
    const BigInt& big = a.d_.size() >= b.d_.size() ? a : b;
    const BigInt& small = a.d_.size() >= b.d_.size() ? b : a;
    BigInt r;
    r.d_.resize(big.d_.size() + 1);
    uint64_t carry = 0;
    for (size_t i = 0; i < big.d_.size(); ++i) {
        uint64_t cur = carry + big.d_[i] + (i < small.d_.size() ? small.d_[i] : 0);
        r.d_[i] = static_cast<uint32_t>(cur);
        carry = cur >> 32;
    }
    r.d_[big.d_.size()] = static_cast<uint32_t>(carry);
    r.trim();
    return r;
}

BigInt BigInt::sub(const BigInt& a, const BigInt& b) {
    if (compare(a, b) < 0) throw FormatError("BigInt::sub: negative result");
    BigInt r;
    r.d_.resize(a.d_.size());
    int64_t borrow = 0;
    for (size_t i = 0; i < a.d_.size(); ++i) {
        int64_t cur = static_cast<int64_t>(a.d_[i]) - borrow - (i < b.d_.size() ? b.d_[i] : 0);
        borrow = cur < 0 ? 1 : 0;
        r.d_[i] = static_cast<uint32_t>(cur);
    }
    r.trim();
    return r;
}

BigInt BigInt::mul(const BigInt& a, const BigInt& b) {
    if (a.is_zero() || b.is_zero()) return BigInt();
    BigInt r;
    r.d_.assign(a.d_.size() + b.d_.size(), 0);
    for (size_t i = 0; i < a.d_.size(); ++i) {
        uint64_t carry = 0;
        for (size_t j = 0; j < b.d_.size(); ++j) {
            uint64_t cur = static_cast<uint64_t>(r.d_[i + j]) +
                           static_cast<uint64_t>(a.d_[i]) * b.d_[j] + carry;
            r.d_[i + j] = static_cast<uint32_t>(cur);
            carry = cur >> 32;
        }
        r.d_[i + b.d_.size()] = static_cast<uint32_t>(carry);
    }
    r.trim();
    return r;
}

BigInt BigInt::shl(size_t bits) const {
    if (d_.empty()) return BigInt();
    size_t limb_shift = bits / 32;
    unsigned bit_shift = static_cast<unsigned>(bits % 32);
    BigInt r;
    r.d_.assign(d_.size() + limb_shift + 1, 0);
    for (size_t i = 0; i < d_.size(); ++i) {
        uint64_t cur = static_cast<uint64_t>(d_[i]) << bit_shift;
        r.d_[i + limb_shift] |= static_cast<uint32_t>(cur);
        r.d_[i + limb_shift + 1] |= static_cast<uint32_t>(cur >> 32);
    }
    r.trim();
    return r;
}

BigInt BigInt::shr(size_t bits) const {
    size_t limb_shift = bits / 32;
    unsigned bit_shift = static_cast<unsigned>(bits % 32);
    if (limb_shift >= d_.size()) return BigInt();
    BigInt r;
    r.d_.assign(d_.size() - limb_shift, 0);
    for (size_t i = limb_shift; i < d_.size(); ++i) {
        uint64_t cur = d_[i];
        if (i + 1 < d_.size()) cur |= static_cast<uint64_t>(d_[i + 1]) << 32;
        r.d_[i - limb_shift] = static_cast<uint32_t>(cur >> bit_shift);
    }
    r.trim();
    return r;
}

// Knuth, TAOCP vol. 2, 4.3.1, algorithm D -- in the formulation of Hacker's
// Delight (divmnu). Base 2^32 limbs, 64-bit intermediates.
void BigInt::divmod(const BigInt& a, const BigInt& b, BigInt& q, BigInt& r) {
    if (b.is_zero()) throw FormatError("BigInt: division by zero");
    if (compare(a, b) < 0) {
        BigInt rem = a;  // `r` may alias `a`
        q = BigInt();
        r = rem;
        return;
    }
    if (b.d_.size() == 1) {
        const uint64_t div = b.d_[0];
        std::vector<uint32_t> qd(a.d_.size(), 0);
        uint64_t rem = 0;
        for (size_t i = a.d_.size(); i-- > 0;) {
            uint64_t cur = (rem << 32) | a.d_[i];
            qd[i] = static_cast<uint32_t>(cur / div);
            rem = cur % div;
        }
        q.d_ = std::move(qd);
        q.trim();
        r = BigInt(rem);
        return;
    }

    const unsigned s = clz32(b.d_.back());
    const size_t n = b.d_.size();
    const size_t m = a.d_.size();
    std::vector<uint32_t> vn(n), un(m + 1);
    for (size_t i = n - 1; i > 0; --i)
        vn[i] = (b.d_[i] << s) | (s ? b.d_[i - 1] >> (32 - s) : 0);
    vn[0] = b.d_[0] << s;
    un[m] = s ? a.d_[m - 1] >> (32 - s) : 0;
    for (size_t i = m - 1; i > 0; --i)
        un[i] = (a.d_[i] << s) | (s ? a.d_[i - 1] >> (32 - s) : 0);
    un[0] = a.d_[0] << s;

    std::vector<uint32_t> qd(m - n + 1, 0);
    const uint64_t base = 1ull << 32;
    for (size_t jj = m - n + 1; jj-- > 0;) {
        const size_t j = jj;
        uint64_t num = (static_cast<uint64_t>(un[j + n]) << 32) | un[j + n - 1];
        uint64_t qhat = num / vn[n - 1];
        uint64_t rhat = num % vn[n - 1];
        while (qhat >= base || qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2])) {
            --qhat;
            rhat += vn[n - 1];
            if (rhat >= base) break;
        }

        int64_t k = 0;
        for (size_t i = 0; i < n; ++i) {
            uint64_t p = qhat * vn[i];
            int64_t t = static_cast<int64_t>(un[i + j]) - k - static_cast<int64_t>(p & 0xffffffffu);
            un[i + j] = static_cast<uint32_t>(t);
            k = static_cast<int64_t>(p >> 32) - (t >> 32);
        }
        int64_t t = static_cast<int64_t>(un[j + n]) - k;
        un[j + n] = static_cast<uint32_t>(t);

        qd[j] = static_cast<uint32_t>(qhat);
        if (t < 0) {  // subtracted once too often: add the divisor back
            --qd[j];
            uint64_t carry = 0;
            for (size_t i = 0; i < n; ++i) {
                uint64_t cur = static_cast<uint64_t>(un[i + j]) + vn[i] + carry;
                un[i + j] = static_cast<uint32_t>(cur);
                carry = cur >> 32;
            }
            un[j + n] += static_cast<uint32_t>(carry);
        }
    }

    BigInt rem;
    rem.d_.assign(n, 0);
    for (size_t i = 0; i < n; ++i)
        rem.d_[i] = (un[i] >> s) | (s ? static_cast<uint32_t>(static_cast<uint64_t>(un[i + 1]) << (32 - s)) : 0);
    rem.trim();
    q.d_ = std::move(qd);
    q.trim();
    r = std::move(rem);
}

BigInt BigInt::mod(const BigInt& m) const {
    BigInt q, r;
    divmod(*this, m, q, r);
    return r;
}

BigInt BigInt::mod_exp(const BigInt& base, const BigInt& exp, const BigInt& m) {
    if (m.is_zero()) throw FormatError("BigInt::mod_exp: modulus is zero");
    if (m.d_.size() == 1 && m.d_[0] == 1) return BigInt();
    if (exp.is_zero()) return BigInt(1);
    BigInt b = base.mod(m);

    if (!m.is_odd()) {
        // Never the case for RSA; kept so the function is total.
        BigInt result(1);
        for (size_t i = exp.bit_length(); i-- > 0;) {
            result = mul(result, result).mod(m);
            if (exp.bit(i)) result = mul(result, b).mod(m);
        }
        return result;
    }

    Montgomery mont(m.d_);
    const size_t k = mont.k();
    auto padded = [&](const BigInt& x) {
        std::vector<uint32_t> v(k, 0);
        std::copy(x.d_.begin(), x.d_.end(), v.begin());
        return v;
    };
    // R^2 mod m, with R = 2^(32k): the factor that moves a number into
    // Montgomery form.
    BigInt r2 = BigInt(1).shl(64 * k).mod(m);
    std::vector<uint32_t> r2v = padded(r2);

    constexpr unsigned kWindow = 4;
    std::vector<std::vector<uint32_t>> table(1u << kWindow, std::vector<uint32_t>(k));
    std::vector<uint32_t> one(k, 0);
    one[0] = 1;
    mont.mul(one.data(), r2v.data(), table[0].data());          // 1 in Montgomery form
    std::vector<uint32_t> bv = padded(b);
    mont.mul(bv.data(), r2v.data(), table[1].data());           // b in Montgomery form
    for (size_t i = 2; i < table.size(); ++i) mont.mul(table[i - 1].data(), table[1].data(), table[i].data());

    std::vector<uint32_t> acc = table[0];
    std::vector<uint32_t> tmp(k);
    const size_t bits = exp.bit_length();
    const size_t windows = (bits + kWindow - 1) / kWindow;
    for (size_t w = windows; w-- > 0;) {
        for (unsigned s = 0; s < kWindow; ++s) {
            mont.mul(acc.data(), acc.data(), tmp.data());
            acc.swap(tmp);
        }
        unsigned digit = 0;
        for (unsigned s = 0; s < kWindow; ++s)
            if (exp.bit(w * kWindow + s)) digit |= 1u << s;
        if (digit) {
            mont.mul(acc.data(), table[digit].data(), tmp.data());
            acc.swap(tmp);
        }
    }
    std::vector<uint32_t> result(k);
    mont.mul(acc.data(), one.data(), result.data());  // leave Montgomery form
    BigInt out;
    out.d_ = std::move(result);
    out.trim();
    return out;
}

}  // namespace abr
