#!/usr/bin/env python3
"""Known-answer vectors for abr's SHA-1/SHA-256/SHA-512, computed with Python's hashlib.

usage: gen_sha_vectors.py <blob-out> <expect-out>

Writes a pseudo-random blob and a list of "alg len chunk hexdigest" lines:
the digest of the first `len` bytes, to be reproduced by feeding them to the
hash in `chunk`-sized update() calls (0 = in one call). The lengths cover every
way the padding can fall (0..129 bytes, around 64/128-byte block boundaries
and the 55/56-byte spill into a second block) and larger buffers that go
through the multi-block fast path; the chunk sizes make update() hit its
partial-buffer, block-aligned and tail code.
"""
import hashlib
import random
import sys

blob_path, expect_path = sys.argv[1], sys.argv[2]
rnd = random.Random(20261003)
lengths = sorted(set(list(range(0, 130)) + [191, 192, 193, 255, 256, 257, 1000, 4095, 4096, 4097,
                                            65535, 65536, 65537, (1 << 20) + 7]))
blob = bytes(rnd.getrandbits(8) for _ in range(max(lengths)))
with open(blob_path, 'wb') as f:
    f.write(blob)
chunks = [0, 1, 7, 63, 64, 65, 4097]
with open(expect_path, 'w', newline='\n') as f:
    for n in lengths:
        for alg in ('sha1', 'sha256', 'sha512'):
            digest = hashlib.new(alg, blob[:n]).hexdigest()
            for c in chunks:
                f.write(f"{alg} {n} {c} {digest}\n")
