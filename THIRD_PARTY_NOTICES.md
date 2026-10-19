# Third-party notices

`abr` itself is GPL-3.0-or-later (see `LICENSE`). A binary of `abr` (`abr-linux-x86_64`, `abr-windows-x86_64.exe`,
`abr-android-arm64`, or one you build with `-DABR_STATIC_BINARY=ON`) is statically linked and so contains code of the
projects below. Their licences ask that the notices travel with a binary: this file is that notice, and it is put next to
the binaries the CI publishes (`THIRD_PARTY_NOTICES.md`).

| Component | Version | Licence | Where in `abr` |
|---|---|---|---|
| zlib | 1.3.2 | zlib licence | gzip (ramdisks, kernels) |
| LZ4 (`lib/`) | 1.10.0 | BSD-2-Clause | lz4 frames and Android's legacy lz4 blocks; the LZ4 parts of Sony SIN containers |
| Zstandard | 1.5.7 | BSD-3-Clause (the project is dual BSD / GPLv2; abr uses it under the BSD licence) | zstd (ramdisks, vendor_boot v4) |
| XZ Utils, liblzma | 5.8.4 | BSD Zero Clause (0BSD) | xz and lzma |
| bzip2 / libbzip2 | 1.0.8 | bzip2 licence (BSD-style) | bzip2 |
| miniLZO (LZO1X subset of LZO) | 2.10 | GPL-2.0-or-later, used under GPL-3.0-or-later with the rest of `abr` | lzo (in the lzop framing); the files are in `third_party/minilzo/` with their own headers |
| the patch code of `loki_tool` (56 bytes) | -- | BSD-2-Clause, Copyright (c) 2013 Dan Rosenberg | LOKI images; the notice is kept in `src/legacy/loki.cpp` |
| the public developer keyblock and key of vboot_reference | -- | BSD-3-Clause, Copyright (c) 2010 The Chromium OS Authors | ChromeOS kernel blobs; the notice is kept in `src/legacy/chromeos_devkeys.cpp` |
| the public AOSP "verity" test key | -- | Apache-2.0 | AVBv1 boot signatures; `src/legacy/avb1_aosp_key.cpp` |

The versions are the ones `cmake/vendor_deps.cmake` and `CMakeLists.txt` pin. The libraries are fetched from their own
repositories when `abr` is built and are not part of this repository. What follows are their licence texts, as the projects
ship them.

What the toolchain links in statically comes with the licences of the toolchain and of the C library, and is not reproduced
here: the C++ runtime of GCC (libstdc++ and libgcc, GPL-3.0-or-later with the GCC Runtime Library Exception) in the Linux and
Windows binaries; glibc (LGPL-2.1-or-later) in the Linux binary, which is fully static; the mingw-w64 runtime and winpthreads in
the Windows binary (permissive licences -- the Zope Public License 2.1, public domain, MIT- and BSD-style; their texts are in the
`copyright` files of the distribution's mingw-w64 packages); and libc++ (Apache-2.0 with LLVM exceptions) in the Android binary,
which uses the system's own bionic. The source of `abr` is this repository, with the build instructions in `README.md`: with
it any of these can be replaced by another build.

The test suite runs other programs as judges (`rkcrc`, `blobpack`, `blobunpack`, `mboot`, `loki_tool`, `pxa-mkbootimg`,
`pxa-unpackbootimg`, `sony_dump`, `elftool`, `futility`, `avbtool`, `boot_signer`, GNU cpio). They are not part of `abr`,
are not linked into it, and are not distributed with it: they are compiled by whoever runs the suite
(`.github/scripts/build_oracles.sh`), or taken from the distribution.

---

## zlib

Copyright notice:

 (C) 1995-2026 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu

## LZ4 library

LZ4 Library
Copyright (c) 2011-2020, Yann Collet
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Zstandard

BSD License

For Zstandard software

Copyright (c) Meta Platforms, Inc. and affiliates. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

 * Neither the name Facebook, nor Meta, nor the names of its contributors may
   be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## XZ Utils (liblzma)

liblzma is under the BSD Zero Clause License:

Permission to use, copy, modify, and/or distribute this
software for any purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

## bzip2

--------------------------------------------------------------------------

This program, "bzip2", the associated library "libbzip2", and all
documentation, are copyright (C) 1996-2019 Julian R Seward.  All
rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. The origin of this software must not be misrepresented; you must 
   not claim that you wrote the original software.  If you use this 
   software in a product, an acknowledgment in the product 
   documentation would be appreciated but is not required.

3. Altered source versions must be plainly marked as such, and must
   not be misrepresented as being the original software.

4. The name of the author may not be used to endorse or promote 
   products derived from this software without specific prior written 
   permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Julian Seward, jseward@acm.org
bzip2/libbzip2 version 1.0.8 of 13 July 2019

--------------------------------------------------------------------------
