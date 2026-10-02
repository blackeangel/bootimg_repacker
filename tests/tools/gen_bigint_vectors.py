#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Known-answer vectors for abr's BigInt, computed with Python's own
arbitrary-precision integers (an implementation that shares no code with
abr). One vector per line, numbers in lowercase hex without 0x:

    add a b r | sub a b r | mul a b r | divmod a b q r | modexp base exp mod r
    shl a n r | shr a n r | bytes a (round trip through big-endian bytes)

    gen_bigint_vectors.py [seed] | abr_unit_tests bigint

The operands are deliberately nasty for Knuth's algorithm D and for
Montgomery multiplication: limbs that are 0, 1, 0x80000000, 0xffffffff, so
the rare "qhat is one too large" and "add the divisor back" paths and the
carry chains run for real, plus RSA-sized random moduli.
"""
import random
import sys

seed = int(sys.argv[1]) if len(sys.argv) > 1 else 20261002
rnd = random.Random(seed)
SPECIAL = [0, 1, 2, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF]


def limb():
    return rnd.choice(SPECIAL) if rnd.random() < 0.6 else rnd.getrandbits(32)


def nasty(limbs):
    v = 0
    for _ in range(limbs):
        v = (v << 32) | limb()
    return v


def rand_bits(bits):
    return rnd.getrandbits(bits) | (1 << (bits - 1))


def h(x):
    return "%x" % x


out = []
for a in (0, 1, 2, 0xFFFFFFFF, 1 << 32, (1 << 64) - 1, 1 << 64, (1 << 2048) - 1):
    for b in (0, 1, 3, 0xFFFFFFFF, 1 << 32, (1 << 64) + 1, (1 << 1024) - 1):
        out.append("add %s %s %s" % (h(a), h(b), h(a + b)))
        out.append("mul %s %s %s" % (h(a), h(b), h(a * b)))
        if a >= b:
            out.append("sub %s %s %s" % (h(a), h(b), h(a - b)))
        if b:
            out.append("divmod %s %s %s %s" % (h(a), h(b), h(a // b), h(a % b)))

for _ in range(4000):
    la, lb = rnd.randint(1, 40), rnd.randint(1, 40)
    a, b = nasty(la), nasty(lb)
    out.append("add %s %s %s" % (h(a), h(b), h(a + b)))
    out.append("mul %s %s %s" % (h(a), h(b), h(a * b)))
    if a < b:
        a, b = b, a
    out.append("sub %s %s %s" % (h(a), h(b), h(a - b)))
    if b:
        out.append("divmod %s %s %s %s" % (h(a), h(b), h(a // b), h(a % b)))
    # same limb count: exercises the single-quotient-limb path
    c = nasty(lb)
    if c:
        out.append("divmod %s %s %s %s" % (h(b), h(c), h(b // c), h(b % c)))

# dividend built as q*d + r: remainders at the very edge of the divisor
for _ in range(2000):
    d = nasty(rnd.randint(2, 20)) | (1 << rnd.randint(31, 600))
    q = nasty(rnd.randint(1, 20))
    r = rnd.choice([0, d - 1, rnd.randrange(d)])
    a = q * d + r
    out.append("divmod %s %s %s %s" % (h(a), h(d), h(q), h(r)))

for _ in range(500):
    a = nasty(rnd.randint(1, 30))
    n = rnd.randint(0, 200)
    out.append("shl %s %d %s" % (h(a), n, h(a << n)))
    out.append("shr %s %d %s" % (h(a), n, h(a >> n)))
    out.append("bytes %s" % h(a))

# modexp: odd moduli of RSA-ish sizes (Montgomery) and a few even ones
for bits in (32, 33, 64, 96, 127, 256, 512, 1024, 2048):
    for _ in range(6 if bits < 1024 else 3):
        m = rand_bits(bits) | 1
        base = rnd.getrandbits(bits + rnd.randint(0, 40))
        exp = rnd.getrandbits(rnd.randint(1, bits))
        out.append("modexp %s %s %s %s" % (h(base), h(exp), h(m), h(pow(base, exp, m))))
for _ in range(30):
    m = nasty(rnd.randint(1, 8)) | 1
    base, exp = nasty(rnd.randint(1, 8)), nasty(rnd.randint(1, 3))
    out.append("modexp %s %s %s %s" % (h(base), h(exp), h(m), h(pow(base, exp, m))))
for _ in range(10):
    m = rand_bits(rnd.randint(16, 200)) & ~1 | 2
    base, exp = rnd.getrandbits(64), rnd.getrandbits(40) + 1
    out.append("modexp %s %s %s %s" % (h(base), h(exp), h(m), h(pow(base, exp, m))))
out.append("modexp 5 0 7 1")
out.append("modexp 0 5 7 0")
out.append("modexp 5 3 1 0")

sys.stdout.write("\n".join(out) + "\n")
