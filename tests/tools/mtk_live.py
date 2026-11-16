#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs abr on the MediaTek images of mk_mtk.py and mk_gfh.py and judges the result with the independent readers of those scripts: the containers of the
small images (md1img, logo, ...), the preloader (a chain of GFH headers), and the AOSP boot images whose kernel and ramdisk carry the MediaTek header (a
header that is not the plain one is kept, a gzip stream that is cut short is told). For each: info, unpack, an untouched pack (byte for byte), an edit (sizes,
hashes, headers, padding made again; what was not touched stays as it was), and damaged images. The pictures of a logo need Pillow: without it those checks
are left out, and the last line says so ("skipped"). One FAIL line per check that does not hold; exit status 1 when there is one.

  mtk_live.py ABR CONTAINERS PRELOADERS BOOTS WORKDIR
      CONTAINERS: what `mk_mtk.py make` made, PRELOADERS: `mk_gfh.py`, BOOTS: `mk_mtk.py boot`
"""
import gzip
import hashlib
import importlib.util
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from livelib import Live, manifest_get, manifest_set, read, same_bytes, script_dir, write  # noqa: E402

ABR, CONT, GFH, BOOT, WORK = sys.argv[1:6]
live = Live(ABR, WORK)
spec = importlib.util.spec_from_file_location("mk_mtk", os.path.join(script_dir(), "mk_mtk.py"))
mk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mk)
try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = None


def untouched(directory, name, fmt):
    """info, unpack, pack of an image that nobody touched. -> the folder of the unpack."""
    img = os.path.join(directory, name)
    rc, text = live.run("info", "-i", img)
    live.check(rc == 0 and ("format: " + fmt) in text, name + ": info says it is " + fmt, text[:300])
    live.check("0x" in text and "offset" in text, name + ": info has the layout with offsets", text[:300])
    out = live.fresh(name + ".u")
    rc, text = live.run("unpack", "-i", img, "-o", out)
    live.check(rc == 0, name + ": unpack", text[-500:])
    live.check("byte-for-byte" in text, name + ": unpack says the repack is identical", text[-300:])
    live.check("0x" in text and "bytes" in text, name + ": unpack writes offsets and sizes", text[-300:])
    new = live.fresh(name + ".new")
    rc, text = live.run("pack", "-i", out, "-o", new)
    live.check(rc == 0 and same_bytes(img, new), name + ": an untouched pack is byte-identical", text[-300:])
    return out


# ================================================================================================================== 1. the containers
with live.section('1. the containers'):
    CONTAINERS = ("md1img.img", "logo.bin", "logo565.bin", "logoalpha.bin", "legacy.img", "align512.img")
    folders = {name: untouched(CONT, name, "mtk_image") for name in CONTAINERS}

# ---------------------------------------------------------------------------------------------------------------- 1a. md1img
with live.section('1a. md1img'):
    # ---- md1img: a modem. The data of the middle section is gzip: the file is the data with that taken off, pack makes the stream again.
    orig = mk.parse(read(os.path.join(CONT, "md1img.img")))
    live.check([s["name"] for s in orig] == ["md1rom", "md1dsp", "md1_file_map"], "md1img: three sections as the independent reader sees them")
    f = folders["md1img.img"]
    live.check(read(os.path.join(f, "00_md1rom")) == orig[0]["data"], "md1img: the first section is its file, byte for byte")
    live.check(gzip.decompress(orig[1]["data"]) == read(os.path.join(f, "01_md1dsp")), "md1img: the second section is its file with the gzip taken off")
    live.check(manifest_get(f, "section1_compression") == "gzip" and manifest_get(f, "section1_level") == "6", "md1img: the manifest says gzip, level 6")
    live.check(read(os.path.join(f, "02_md1_file_map")) == orig[2]["data"], "md1img: the third section is its file")

    out = live.fresh("md1img.edit")
    live.run("unpack", "-i", os.path.join(CONT, "md1img.img"), "-o", out)
    rom_new = orig[0]["data"] + b"\x77" * 1001  # the sections behind it move on
    dsp_new = bytes(range(256)) * 50 + b"edited"
    write(os.path.join(out, "00_md1rom"), rom_new)
    write(os.path.join(out, "01_md1dsp"), dsp_new)
    new = live.fresh("md1img.edited")
    rc, text = live.run("pack", "-i", out, "-o", new)
    live.check(rc == 0, "md1img: pack after two sections changed", text[-400:])
    if rc == 0:
        d = read(new)
        secs = mk.parse(d)
        live.check([s["name"] for s in secs] == ["md1rom", "md1dsp", "md1_file_map"], "md1img edited: the sections are the same three")
        live.check(secs[0]["data"] == rom_new, "md1img edited: the first section is the new file")
        live.check(gzip.decompress(secs[1]["data"]) == dsp_new, "md1img edited: the second section is a gzip stream of the new file")
        live.check(secs[2]["data"] == orig[2]["data"], "md1img edited: the third section is untouched")
        live.check(all(s["header_at"] % 16 == 0 for s in secs), "md1img edited: every header is on a multiple of 16")
        live.check(secs[-1]["last"] and not any(s["last"] for s in secs[:-1]), "md1img edited: the last section is the one that says so")
        live.check([struct.unpack_from("<I", d, s["header_at"] + 40)[0] for s in secs] == [0, 0x10000000, 0xFFFFFFFF], "md1img edited: the load addresses are kept")
        live.check(len(d) == secs[-1]["at"] + secs[-1]["size"], "md1img edited: the content is longer than the image was, so there is no fill behind it (pad_to is a floor, not a length)", str(len(d)))

    # the same image made shorter: the size of the file stays what it was, the fill is the byte of the original
    out = live.fresh("md1img.shrink")
    live.run("unpack", "-i", os.path.join(CONT, "md1img.img"), "-o", out)
    write(os.path.join(out, "00_md1rom"), orig[0]["data"][:3000])
    new = live.fresh("md1img.shrunk")
    rc, text = live.run("pack", "-i", out, "-o", new)
    if live.check(rc == 0, "md1img: pack after the first section was made shorter", text[-400:]):
        d, whole = read(new), len(read(os.path.join(CONT, "md1img.img")))
        secs = mk.parse(d)
        end = secs[-1]["at"] + secs[-1]["size"]
        live.check(len(d) == whole and d[end:] == b"\xff" * (whole - end) and whole > end, "md1img shrunk: the file is as long as the original, the rest is the 0xFF fill", "%d of %d" % (len(d), whole))
        live.check(secs[0]["data"] == orig[0]["data"][:3000] and secs[2]["data"] == orig[2]["data"] and gzip.decompress(secs[1]["data"]) == gzip.decompress(orig[1]["data"]),
                   "md1img shrunk: the three sections hold what they should")

# ---------------------------------------------------------------------------------------------------------------- 1b. legacy.img
with live.section('1b. legacy.img'):
    # ---- legacy.img: headers of the older kind, a name that is a path, two sections of one name, padding that is not uniform
    f = folders["legacy.img"]
    files = sorted(n for n in os.listdir(f) if not n.startswith(".") and n != "manifest.txt")
    live.check(len(files) == 3 and not any(os.sep in n for n in files), "legacy: three files, whatever the names of the sections", str(files))
    live.check(not os.path.exists(os.path.join(WORK, "evil")) and not os.path.exists(os.path.join(f, "..", "evil")), "legacy: a section named ../evil/name writes nothing outside the folder")
    live.check(len(set(files)) == 3, "legacy: two sections of one name are two files")

# ---------------------------------------------------------------------------------------------------------------- 1c. align512
with live.section('1c. align512'):
    # ---- align512: the headers stay on multiples of 512 after an edit
    out = live.fresh("align512.edit")
    live.run("unpack", "-i", os.path.join(CONT, "align512.img"), "-o", out)
    write(os.path.join(out, "00_tee1"), b"Z" * 1500)
    new = live.fresh("align512.edited")
    rc, text = live.run("pack", "-i", out, "-o", new)
    if live.check(rc == 0, "align512: pack after a change", text[-300:]):
        secs = mk.parse(read(new))
        live.check([s["size"] for s in secs] == [1500, 33] and all(s["header_at"] % 512 == 0 for s in secs), "align512 edited: the headers are on multiples of 512", str([(s["size"], s["header_at"]) for s in secs]))

# ---------------------------------------------------------------------------------------------------------------- 1d. logos
with live.section('1d. logos'):
    # ---- a logo is a table of pictures: PNG files, 4 bytes (BGRA), 2 (RGB565) or 3 a pixel
    def swap_rb(im):
        c0, c1, c2, a = im.split()
        return Image.merge("RGBA", (c2, c1, c0, a))


    def logo_streams(d):
        sec = mk.parse(d)[0]["data"]
        count, total = struct.unpack_from("<II", sec, 0)
        offs = list(struct.unpack_from("<%dI" % count, sec, 8)) + [total]
        return [sec[offs[i]:offs[i + 1]] for i in range(count)]


    if Image is None:
        print("SKIP: the pictures of a logo (Pillow is not installed)")
    else:
        f = folders["logo.bin"]
        streams = logo_streams(read(os.path.join(CONT, "logo.bin")))
        for i, (w, h, seed) in enumerate(((240, 320, 1), (240, 320, 2), (480, 800, 3))):
            png = os.path.join(f, "00_logo", "img-%03d.png" % i)
            want = swap_rb(Image.frombytes("RGBA", (w, h), mk.bgra(w, h, seed))).tobytes()
            got = Image.open(png).convert("RGBA")
            live.check(got.size == (w, h) and got.tobytes() == want, "logo: picture %d is %dx%d and its pixels are the ones of the stream" % (i, w, h))
        out = live.fresh("logo.edit")
        live.run("unpack", "-i", os.path.join(CONT, "logo.bin"), "-o", out)
        png = os.path.join(out, "00_logo", "img-001.png")
        im = Image.open(png).convert("RGBA")
        ImageDraw.Draw(im).rectangle([10, 10, 100, 60], fill=(250, 10, 120, 255))
        im.save(png)
        new = live.fresh("logo.edited")
        rc, text = live.run("pack", "-i", out, "-o", new)
        if live.check(rc == 0, "logo: pack after a picture was drawn on", text[-400:]):
            st = logo_streams(read(new))
            live.check(len(st) == 3, "logo edited: still three pictures")
            live.check(zlib.decompress(st[1]) == swap_rb(im).tobytes(), "logo edited: picture 1 is the edited pixels, as BGRA")
            live.check(st[0] == streams[0] and st[2] == streams[2], "logo edited: the pictures that were not touched are the bytes they were")
        # a picture of another size is a picture the bootloader would draw wrong: packed all the same (a person may mean it), with a warning that names both sizes
        out = live.fresh("logo.resized")
        live.run("unpack", "-i", os.path.join(CONT, "logo.bin"), "-o", out)
        Image.open(os.path.join(out, "00_logo", "img-000.png")).convert("RGBA").resize((100, 100)).save(os.path.join(out, "00_logo", "img-000.png"))
        new = live.fresh("logo.resized.img")
        rc, text = live.run("pack", "-i", out, "-o", new)
        live.check(rc == 0 and "warning" in text and "100x100" in text and "240x320" in text, "logo: a picture of another size is packed, with a warning that names both sizes", text[-400:])
        if rc == 0:
            live.check(len(zlib.decompress(logo_streams(read(new))[0])) == 100 * 100 * 4, "logo resized: the picture is stored with the pixels that it has")

        # 16-bit pictures, and the ones that cannot be pictures
        f = folders["logo565.bin"]
        live.check(os.path.exists(os.path.join(f, "00_logo", "img-000.png")) and os.path.exists(os.path.join(f, "00_logo", "img-002.bin")), "logo565: pictures of a size abr knows are PNG, the others stay as they are")
        live.check(manifest_get(f, "section0_logo_format") == "rgb565", "logo565: the manifest says rgb565")
        st = logo_streams(read(os.path.join(CONT, "logo565.bin")))
        live.check(read(os.path.join(f, "00_logo", "img-003.bin")) == st[3], "logo565: bytes that are no zlib stream stay as they are")
        out = live.fresh("logo565.edit")
        live.run("unpack", "-i", os.path.join(CONT, "logo565.bin"), "-o", out)
        png = os.path.join(out, "00_logo", "img-000.png")
        im = Image.open(png).convert("RGB")
        ImageDraw.Draw(im).rectangle([0, 0, 50, 50], fill=(255, 0, 0))
        im.save(png)
        new = live.fresh("logo565.edited")
        rc, text = live.run("pack", "-i", out, "-o", new)
        if live.check(rc == 0, "logo565: pack after a picture was drawn on", text[-300:]):
            st2 = logo_streams(read(new))
            raw = zlib.decompress(st2[0])
            px = struct.unpack_from("<H", raw, 0)[0]
            live.check(len(raw) == 480 * 800 * 2 and px == 0xF800, "logo565 edited: the first pixel is red in RGB565 (0xF800), %d bytes" % len(raw), hex(px))
            live.check(st2[1:] == st[1:], "logo565 edited: the other pictures are the bytes they were")

        # alpha: a picture whose pixels all have one alpha is a PNG without an alpha channel, and keeps that alpha
        f = folders["logoalpha.bin"]
        live.check(manifest_get(f, "section0_p0_alpha") == "128", "logoalpha: the constant alpha of picture 0 is in the manifest")
        live.check(Image.open(os.path.join(f, "00_logo", "img-000.png")).mode == "RGB" and Image.open(os.path.join(f, "00_logo", "img-001.png")).mode == "RGBA",
                   "logoalpha: no alpha channel for the constant alpha, one for the gradient")
        out = live.fresh("logoalpha.edit")
        live.run("unpack", "-i", os.path.join(CONT, "logoalpha.bin"), "-o", out)
        png = os.path.join(out, "00_logo", "img-000.png")
        im = Image.open(png).convert("RGB")
        ImageDraw.Draw(im).rectangle([5, 5, 60, 60], fill=(1, 2, 3))
        im.save(png)
        new = live.fresh("logoalpha.edited")
        rc, text = live.run("pack", "-i", out, "-o", new)
        if live.check(rc == 0, "logoalpha: pack after the picture without alpha was drawn on", text[-300:]):
            raw = zlib.decompress(logo_streams(read(new))[0])
            live.check(len(raw) == 240 * 320 * 4 and set(raw[3::4]) == {128}, "logoalpha edited: every pixel still has alpha 128")

# ======================================================================================================== 2. the preloader (GFH chain)
with live.section('2. the preloader (GFH chain)'):
    def preloader(path):
        """-> (start of the first header, FILE_INFO as a dict, the loader (what the headers say is the code), the signature bytes, problems)"""
        d = read(path)
        start = struct.unpack_from("<I", d, 0x20C)[0] if d[:9] in (b"EMMC_BOOT", b"SF_BOOT\0\0") else 0
        problems = []
        if d[start + 8:start + 17] != b"FILE_INFO":
            return start, {}, b"", b"", ["no FILE_INFO at %#x" % start]
        fi = dict(zip(("file_ver", "file_type", "flash", "sig_type", "load", "total", "max_size", "hdr", "sig_len", "jump", "processed"),
                      struct.unpack_from("<IHBBIIIIIII", d, start + 8 + 12)[:11]))
        total, hdr, sig_len = fi["total"], fi["hdr"], fi["sig_len"]
        if hdr + sig_len > total or start + total > len(d):
            problems.append("sizes: total %d, headers %d, signature %d, file %d from %d" % (total, hdr, sig_len, len(d), start))
            return start, fi, b"", b"", problems
        loader = d[start + hdr:start + total - sig_len]
        sig = d[start + total - sig_len:start + total]
        if fi["sig_type"] == 1 and sig != hashlib.sha256(d[start:start + total - sig_len]).digest():
            problems.append("the SHA-256 at the end is not the hash of the image")
        return start, fi, loader, sig, problems


    PRELOADERS = ("raw_sha256.bin", "emmc_sha256.img", "raw_sig5.bin", "emmc_none.img", "raw_gzip_loader.bin", "sf_boot.img")
    for name in PRELOADERS:
        f = untouched(GFH, name, "mtk_preloader")
        start, fi, loader, sig, problems = preloader(os.path.join(GFH, name))
        live.check(not problems, name + ": the independent reader finds the original consistent", str(problems))
        gz = name == "raw_gzip_loader.bin"
        code = read(os.path.join(f, "loader.bin"))
        live.check((gzip.decompress(loader) if gz else loader) == code, name + ": loader.bin is the code (the gzip taken off where there is some)")
        live.check(manifest_get(f, "loader_compression") == ("gzip" if gz else "none"), name + ": the manifest says how the loader was compressed")
        # the code is changed: the sizes of FILE_INFO and the signature are made again
        new_code = bytes((i * 5 + (i >> 6)) & 0xFF for i in range(30001))
        write(os.path.join(f, "loader.bin"), new_code)
        new = live.fresh(name + ".edited")
        rc, text = live.run("pack", "-i", f, "-o", new)
        if not live.check(rc == 0, name + ": pack after the code changed", text[-400:]):
            continue
        start2, fi2, loader2, sig2, problems2 = preloader(new)
        live.check(not problems2, name + ": the edited image is consistent (sizes, and the SHA-256 where there is one)", str(problems2))
        live.check((gzip.decompress(loader2) if gz else loader2) == new_code, name + ": the new code is in the image")
        live.check(fi2["load"] == fi["load"] and fi2["max_size"] == fi["max_size"] and fi2["jump"] == fi["jump"] and fi2["sig_type"] == fi["sig_type"],
                   name + ": the load address, the limit, the jump and the kind of signature are kept")
        if fi["sig_type"] == 5:
            live.check(sig2 == sig, name + ": a signature that abr cannot make is kept as it was")
            live.check("abr cannot make it again" in text and "boot ROM" in text, name + ": pack warns that the kept signature no longer matches the changed image", text[-700:])
        else:
            live.check("cannot make it again" not in text, name + ": no warning about a signature that is made again (or that there is none)", text[-300:])
        d2 = read(new)
        if d2[:9] in (b"EMMC_BOOT", b"SF_BOOT\0\0"):
            live.check(len(d2) % 0x200 == 0 and struct.unpack_from("<I", d2, 0x210)[0] == len(d2), name + ": the size in BRLYT is the size of the file, a multiple of 0x200", "%d" % len(d2))
        # abr reads what it wrote
        out2 = live.fresh(name + ".e2")
        rc, text = live.run("unpack", "-i", new, "-o", out2)
        live.check(rc == 0 and "byte-for-byte" in text and read(os.path.join(out2, "loader.bin")) == new_code, name + ": unpack of the edited image", text[-300:])

# ============================================================================================ 3. boot images with the MediaTek header
with live.section('3. boot images with the MediaTek header'):
    def aosp0(path):
        """The kernel and the ramdisk blobs of an AOSP boot image, header version 0: (kernel, ramdisk, page size)."""
        d = read(path)
        ksz, _ka, rsz, _ra, _ssz, _sa, _ta, page = struct.unpack_from("<8I", d, 8)
        kernel = d[page:page + ksz]
        rd_at = page + (ksz + page - 1) // page * page
        return kernel, d[rd_at:rd_at + rsz], page


    def blob_header(blob):
        return blob[:512], blob[512:]


    kernel_plain = None
    f = untouched(BOOT, "boot_plain.img", "boot")
    k_blob, r_blob, page = aosp0(os.path.join(BOOT, "boot_plain.img"))
    kh, kp = blob_header(k_blob)
    rh, rp = blob_header(r_blob)
    live.check(manifest_get(f, "kernel_mtk_name") == "KERNEL" and manifest_get(f, "ramdisk_mtk_name") == "ROOTFS", "boot_plain: the manifest names the MediaTek headers")
    live.check(manifest_get(f, "kernel_mtk_header_file") is None and manifest_get(f, "ramdisk_mtk_header_file") is None, "boot_plain: a plain header is no file")
    live.check(read(os.path.join(f, "kernel")) == gzip.decompress(kp), "boot_plain: kernel is the payload with the header and the gzip taken off")
    live.check(read(os.path.join(f, "ramdisk.cpio")) == gzip.decompress(rp), "boot_plain: ramdisk.cpio is the archive")
    new_kernel = bytes((i * 3) & 0xFF for i in range(7777))
    write(os.path.join(f, "kernel"), new_kernel)
    new = live.fresh("boot_plain.edited")
    rc, text = live.run("pack", "-i", f, "-o", new)
    if live.check(rc == 0, "boot_plain: pack after the kernel changed", text[-300:]):
        k2, r2, _ = aosp0(new)
        h2, p2 = blob_header(k2)
        live.check(struct.unpack_from("<I", h2, 0)[0] == mk.MAGIC and struct.unpack_from("<I", h2, 4)[0] == len(p2) and h2[8:14] == b"KERNEL" and h2[14:] == b"\0" * 26 + b"\xff" * 472,
                   "boot_plain edited: the plain header again, with the size of the new payload")
        live.check(gzip.decompress(p2) == new_kernel, "boot_plain edited: the payload is a gzip stream of the new kernel")
        live.check(r2 == r_blob, "boot_plain edited: the ramdisk blob is untouched")

    f = untouched(BOOT, "boot_odd.img", "boot")
    k_blob, r_blob, page = aosp0(os.path.join(BOOT, "boot_odd.img"))
    kh, kp = blob_header(k_blob)
    rh, rp = blob_header(r_blob)
    live.check(read(os.path.join(f, "kernel.mtk_header")) == kh, "boot_odd: the header of the kernel is a file, as it was")
    live.check(read(os.path.join(f, "ramdisk.cpio.mtk_header")) == rh, "boot_odd: the header of the ramdisk is a file, as it was")
    live.check(manifest_get(f, "ramdisk_mtk_size_extra") == "12", "boot_odd: the ramdisk holds 12 bytes more than its header says, and the manifest says so")
    new_kernel = bytes((i * 7) & 0xFF for i in range(5000))
    write(os.path.join(f, "kernel"), new_kernel)
    new_rd = mk.newc([("init", 0o100755, b"edited\n" * 30)])
    write(os.path.join(f, "ramdisk.cpio"), new_rd)
    if os.path.isdir(os.path.join(f, "ramdisk")):
        import shutil
        shutil.rmtree(os.path.join(f, "ramdisk"))  # (the archive file is what was edited)
    new = live.fresh("boot_odd.edited")
    rc, text = live.run("pack", "-i", f, "-o", new)
    if live.check(rc == 0, "boot_odd: pack after the kernel and the ramdisk changed", text[-300:]):
        k2, r2, _ = aosp0(new)
        h2, p2 = blob_header(k2)
        live.check(h2[:4] == kh[:4] and h2[8:] == kh[8:] and struct.unpack_from("<I", h2, 4)[0] == len(p2), "boot_odd edited: the header of the kernel is as it was, but for the size it declares")
        live.check(gzip.decompress(p2) == new_kernel, "boot_odd edited: the kernel payload is the new one")
        h2, p2 = blob_header(r2)
        live.check(h2[:4] == rh[:4] and h2[8:] == rh[8:] and struct.unpack_from("<I", h2, 4)[0] == len(p2) - 12, "boot_odd edited: the header of the ramdisk is as it was; the size is 12 less than the payload, as before")
        live.check(gzip.decompress(p2) == new_rd, "boot_odd edited: the ramdisk payload is the new archive")

    # a stream that ends before its end: told when it is unpacked, kept as it is when nothing of it changes, whole when it is changed
    f_whole = untouched(BOOT, "boot_whole.img", "boot")
    out = live.fresh("boot_whole.u2")
    rc, text = live.run("unpack", "-i", os.path.join(BOOT, "boot_whole.img"), "-o", out)
    live.check("cut short" not in text, "boot_whole: no word about a stream that is cut short where there is none", text[-300:])
    f = untouched(BOOT, "boot_cut.img", "boot")
    out = live.fresh("boot_cut.u2")
    rc, text = live.run("unpack", "-i", os.path.join(BOOT, "boot_cut.img"), "-o", out)
    live.check(text.count("is cut short") == 2 and "kernel (gzip)" in text and "ramdisk.cpio (gzip)" in text, "boot_cut: unpack says of the kernel and of the ramdisk that the stream is cut short", text[-600:])
    k_blob, r_blob, page = aosp0(os.path.join(BOOT, "boot_cut.img"))
    manifest_set(f, "cmdline", "bootopt=64S3,32N2,32N2 changed=1")
    new = live.fresh("boot_cut.cmdline")
    rc, text = live.run("pack", "-i", f, "-o", new)
    if live.check(rc == 0, "boot_cut: pack after only the command line changed", text[-300:]):
        k2, r2, _ = aosp0(new)
        live.check(k2 == k_blob and r2 == r_blob, "boot_cut: the streams that nobody touched stay the bytes they were, cut short as they were")
    kernel_cut = read(os.path.join(f, "kernel"))
    write(os.path.join(f, "kernel"), kernel_cut + b"more bytes")
    new = live.fresh("boot_cut.edited")
    rc, text = live.run("pack", "-i", f, "-o", new)
    if live.check(rc == 0, "boot_cut: pack after the kernel changed", text[-300:]):
        k2, r2, _ = aosp0(new)
        h2, p2 = blob_header(k2)
        live.check(gzip.decompress(p2) == kernel_cut + b"more bytes", "boot_cut edited: the kernel is a whole gzip stream now (the check value and the end are there)")
        live.check(struct.unpack_from("<I", h2, 4)[0] == len(p2), "boot_cut edited: the header declares the size of the new stream")
        live.check(r2 == r_blob, "boot_cut edited: the ramdisk is still the bytes it was")

# ======================================================================================================================= 4. damaged images
with live.section('4. damaged images'):
    runs = 0
    for directory, names in ((CONT, CONTAINERS), (GFH, PRELOADERS), (BOOT, ("boot_plain.img", "boot_odd.img", "boot_cut.img"))):
        for name in names:
            runs += live.damaged(name, read(os.path.join(directory, name)), seed=20261113, head=0x1200)
print("damaged-image runs: %d" % runs)
if Image is None:
    print("skipped: the pictures of a logo (Pillow is not installed)")
sys.exit(live.finish("mtk"))
