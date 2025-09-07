#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, struct, argparse
from io import BytesIO
from collections import defaultdict

# =========================
#   Shuffle! Essence+ keys
# =========================
SHUFFLE_ESSENCE_PLUS = {
    "BaseKey": {"Key1": 2780408939, "Key2": 2590219749},
    "ContentXor": 93,
    "RotatePattern": 829710981,
    "FileKeys": {
        "SYS":   {"Key1": 2741198788, "Key2": 2705999494},
        "CHR":   {"Key1": 1312048700, "Key2": 3034103149},
        "PIC":   {"Key1": 4120032587, "Key2": 2899130908},
        "BGM":   {"Key1": 3305975766, "Key2": 3365791657},
        "SE":    {"Key1": 3922546203, "Key2": 2561514851},
        "VOICE": {"Key1": 2254081358, "Key2": 1949148053},
        "DATA":  {"Key1": 3466945094, "Key2": 3729193382},
    },
}

# -------- constants / helpers --------
MAGIC = b"LPK1"
ROTATE_PATTERN = SHUFFLE_ESSENCE_PLUS["RotatePattern"]
CONTENT_XOR    = SHUFFLE_ESSENCE_PLUS["ContentXor"]

def rotl32(v, r): r &= 31; return ((v << r) | (v >> (32 - r))) & 0xFFFFFFFF
def rotr32(v, r): r &= 31; return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF
def rotl8(v, r):  r &= 7;  return ((v << r) | (v >> (8 - r))) & 0xFF
def rotr8(v, r):  r &= 7;  return ((v >> r) | (v << (8 - r))) & 0xFF

def calculate_file_key(base_name: str):
    """Derive final (k1,k2) from base name (e.g., 'PIC') using Essence+ key schedule."""
    file_key = SHUFFLE_ESSENCE_PLUS["FileKeys"].get(base_name.upper())
    if not file_key:
        raise SystemExit(f"No known keys for {base_name}.LPK; known: {', '.join(sorted(SHUFFLE_ESSENCE_PLUS['FileKeys']))}")

    key1 = SHUFFLE_ESSENCE_PLUS["BaseKey"]["Key1"]
    key2 = SHUFFLE_ESSENCE_PLUS["BaseKey"]["Key2"]

    try:
        name_bytes = base_name.encode("shift_jis")
    except:
        name_bytes = base_name.encode("cp932", errors="ignore")

    for i in range(len(name_bytes)):
        e = len(name_bytes) - 1 - i
        key1 ^= name_bytes[e]
        key2 ^= name_bytes[i]
        key1 = rotr32(key1, 7)
        key2 = rotl32(key2, 7)

    key1 ^= file_key["Key1"]
    key2 ^= file_key["Key2"]
    return key1 & 0xFFFFFFFF, key2 & 0xFFFFFFFF

# ---- index encrypt/decrypt (symmetric) ----
def crypt_index_words(buf: bytearray, key2: int):
    pat = ROTATE_PATTERN & 0xFFFFFFFF
    for i in range(len(buf)//4):
        off = i*4
        w, = struct.unpack_from("<I", buf, off)
        w ^= key2
        struct.pack_into("<I", buf, off, w & 0xFFFFFFFF)
        pat = rotl32(pat, 4)
        key2 = rotr32(key2, pat & 31)

# ---- entry prefix (first 0x100) encrypt/decrypt (symmetric XOR schedule) ----
def crypt_entry_prefix(buf: bytearray, key1: int, prefix_len=0x100):
    n = min(len(buf), prefix_len)
    pat = ROTATE_PATTERN & 0xFFFFFFFF
    key = key1 & 0xFFFFFFFF
    for i in range(0, n - (n % 4), 4):
        w, = struct.unpack_from("<I", buf, i)
        w ^= key
        struct.pack_into("<I", buf, i, w & 0xFFFFFFFF)
        # use the *entry* rotation order (matches widely-used tools)
        pat = rotr32(pat, 4)
        key = rotl32(key, pat & 31)

# ---- whole-crypt (content-wide) ----
def whole_encrypt(buf: bytearray):
    # inverse of the extractor’s decrypt: rotl8 first, then xor
    for i in range(len(buf)):
        buf[i] = rotl8(buf[i], 4) ^ CONTENT_XOR

def whole_decrypt(buf: bytearray):
    for i in range(len(buf)):
        v = buf[i] ^ CONTENT_XOR
        buf[i] = rotr8(v, 4)

# =========================
#   LPK index/trie builder
# =========================
class TrieNode:
    __slots__ = ("children", "terminal", "_start")
    def __init__(self):
        self.children = {}
        self.terminal = None
        self._start = -1

def build_trie(names_cp932_bytes, name_to_index):
    root = TrieNode()
    for name_bytes in names_cp932_bytes:
        node = root
        for b in name_bytes:
            node = node.children.setdefault(b, TrieNode())
        node.terminal = name_to_index[name_bytes]
    return root

def serialize_trie(root: TrieNode, width_bytes=4) -> bytes:
    """
    Layout: node := [count:1] { letter:1, offset:width }^count
      - letter != 0 : offset = signed relative to (pos_after_offset) to child node start
      - letter == 0 : offset = entry_index (0..N-1)
    """
    if width_bytes not in (2,4): raise ValueError("width must be 2 or 4")
    buf = bytearray()
    fixups = []  # (pos_of_offset, child_node)

    def write_node(node: TrieNode):
        start = len(buf)
        entries = []
        # Terminal first (letter=0) if present
        if node.terminal is not None:
            entries.append((0, node.terminal))
        # Then children sorted by byte
        for letter in sorted(node.children.keys()):
            entries.append((letter, node.children[letter]))

        buf.append(len(entries) & 0xFF)
        for letter, val in entries:
            buf.append(letter & 0xFF)
            if letter == 0:
                # write entry index directly (unsigned)
                if width_bytes == 4:
                    buf.extend(struct.pack("<I", val))
                else:
                    if val > 0xFFFF: raise ValueError("entry index too large for 2-byte offsets")
                    buf.extend(struct.pack("<H", val))
            else:
                # placeholder, patch later
                off_pos = len(buf)
                buf.extend(b"\x00\x00\x00\x00" if width_bytes == 4 else b"\x00\x00")
                fixups.append((off_pos, val))  # val is child node

        # write children bodies after header
        for letter, val in entries:
            if letter != 0:
                write_node(val)

        # record start for fixup math
        node._start = start  # attach dynamically

    write_node(root)

    # Patch child relative offsets
    for pos, child in fixups:
        child_start = child._start
        after_offset = pos + (4 if width_bytes == 4 else 2)
        rel = child_start - after_offset  # signed
        if width_bytes == 4:
            struct.pack_into("<i", buf, pos, rel)
        else:
            if not (0 <= rel <= 0xFFFF):
                raise ValueError("relative offset does not fit in 2 bytes")
            struct.pack_into("<H", buf, pos, rel)

    return bytes(buf)

# =========================
#   Repack core
# =========================
def read_flags_prefix_from_original(orig_lpk_path: str, base_name: str):
    """Read flags and prefix from an original LPK (recommended)."""
    k1, k2 = calculate_file_key(base_name)
    with open(orig_lpk_path, "rb") as f:
        if f.read(4) != MAGIC: raise SystemExit("Original LPK has bad magic")
        header_value, = struct.unpack("<I", f.read(4))
        tmp = header_value ^ k2
        flags = (tmp >> 24) & 0xFF
        table_size = tmp & 0xFFFFFF
        if flags & 0x01:  # aligned
            table_size = (table_size << 11) - 8
        table = bytearray(f.read(table_size))
        crypt_index_words(table, k2)  # decrypt (symmetric)
    # parse prefix from index
    s = BytesIO(table)
    file_count, = struct.unpack("<I", s.read(4))
    pref_len = s.read(1)[0]
    prefix = s.read(pref_len) if pref_len else b""
    # 1 byte offset-size flag; 4 bytes letter size (skip)
    offset_size_flag = s.read(1)[0]  # 0 -> 2 bytes, else 4 bytes
    width = 4 if offset_size_flag != 0 else 2
    return flags, prefix, width

def repack_lpk(input_dir: str, out_file: str, orig_lpk: str|None,
               force_flags: int|None, whole: bool|None, enc: bool|None,
               width_bytes: int|None, keep_prefix: bool, auto_strip_prefix: bool):
    # Figure archive basename (keys depend on this)
    base_name = os.path.splitext(os.path.basename(out_file))[0].upper()
    k1, k2 = calculate_file_key(base_name)

    # Gather files
    files = []
    for root, _, fnames in os.walk(input_dir):
        for fn in fnames:
            rel = os.path.relpath(os.path.join(root, fn), input_dir)
            rel = rel.replace("\\", "/")
            files.append(rel)
    if not files:
        raise SystemExit("No files found to pack.")

    # Sort for determinism (SJIS byte order)
    def to_cp932_bytes(name):
        try:   return name.encode("shift_jis")
        except: return name.encode("cp932", errors="ignore")
    files_bytes = [to_cp932_bytes(n) for n in files]
    files_sorted = [x for _, x in sorted(zip(files_bytes, files), key=lambda t: t[0])]
    files_bytes_sorted = [to_cp932_bytes(n) for n in files_sorted]

    # Read flags/prefix (clone from original unless overridden)
    if orig_lpk:
        flags, prefix_bytes, cloned_width = read_flags_prefix_from_original(orig_lpk, base_name)
        if width_bytes is None: width_bytes = cloned_width
    else:
        # default: encrypted only, not packed, not aligned, not whole
        flags = 0x04
        prefix_bytes = b""
        if width_bytes is None: width_bytes = 4

    if force_flags is not None:
        flags = force_flags & 0xFF
    if enc is not None:
        flags = (flags | 0x04) if enc else (flags & ~0x04)
    if whole is not None:
        flags = (flags | 0x10) if whole else (flags & ~0x10)

    if width_bytes not in (2,4):
        raise SystemExit("--width must be 2 or 4")

    # Build name -> index mapping
    name_to_index = {nb: i for i, nb in enumerate(files_bytes_sorted)}
    # Build trie and serialize
    trie = build_trie(files_bytes_sorted, name_to_index)
    letter_table = serialize_trie(trie, width_bytes=width_bytes)

    # Entry table params
    packed = bool(flags & 0x08)
    aligned = bool(flags & 0x01)
    whole_flag = bool(flags & 0x10)
    enc_flag = bool(flags & 0x04)

    if packed:
        raise SystemExit("This repacker does not implement compression. Clear the Packed bit (0x08).")

    entry_size = 13 if packed else 9

    # Build entry data (transform content now to know sizes)
    entries_bytes = []
    sizes = []
    # Decide whether to strip prefix from inputs (the extractor you used likely prepended it)
    for name in files_sorted:
        p = os.path.join(input_dir, name.replace("/", os.sep))
        with open(p, "rb") as f:
            data = bytearray(f.read())

        # If the index has a prefix and user wants automatic cleanup, strip it when present
        if prefix_bytes and auto_strip_prefix and data.startswith(prefix_bytes):
            data = bytearray(data[len(prefix_bytes):])

        # Whole-crypt if requested by flags
        if whole_flag:
            whole_encrypt(data)

        # Encrypt entry prefix (0x100 bytes)
        if enc_flag and len(data) > 0:
            crypt_entry_prefix(data, k1, prefix_len=0x100)

        # Optionally re-apply prefix into stored entry bytes (rare; default is to keep entries *without* prefix)
        if keep_prefix and prefix_bytes:
            data = bytearray(prefix_bytes) + data

        entries_bytes.append(bytes(data))
        sizes.append(len(data))

    # Compute index sizes
    # index layout: [count:4][pref_len:1][prefix][width_flag:1][letter_len:4][letter_table][entries...]
    offset_size_flag = 0 if width_bytes == 2 else 1
    prefix_len = len(prefix_bytes)
    letter_len = len(letter_table)
    entries_len = len(files_sorted) * entry_size
    index_plain_size = 4 + 1 + prefix_len + 1 + 4 + letter_len + entries_len

    # Compute data start (header 8 bytes + encrypted index size)
    data_start = 8 + index_plain_size

    # Build entries table with absolute offsets
    offsets = []
    cur = data_start
    for sz in sizes:
        # Align if needed (rare)
        if aligned:
            # actual offsets must be 2KB aligned if the reader expects <<11
            pad = (-cur) & 0x7FF
            cur += pad
        offsets.append(cur)
        cur += sz

    # Compose index (plain), then encrypt it
    index_plain = bytearray(index_plain_size)
    s = 0
    struct.pack_into("<I", index_plain, s, len(files_sorted)); s += 4
    index_plain[s] = prefix_len & 0xFF; s += 1
    if prefix_len:
        index_plain[s:s+prefix_len] = prefix_bytes; s += prefix_len
    index_plain[s] = offset_size_flag; s += 1
    struct.pack_into("<I", index_plain, s, letter_len); s += 4
    index_plain[s:s+letter_len] = letter_table; s += letter_len

    # Fill entries
    for i in range(len(files_sorted)):
        entry_flags = 0  # not using per-entry flags
        off = offsets[i]
        szc = sizes[i]
        if aligned:
            off_stored = off >> 11
        else:
            off_stored = off
        # pack entry
        struct.pack_into("B", index_plain, s, entry_flags); s += 1
        struct.pack_into("<I", index_plain, s, off_stored); s += 4
        struct.pack_into("<I", index_plain, s, szc); s += 4
        if packed:
            # not used here
            struct.pack_into("<I", index_plain, s, szc); s += 4

    # Encrypt index
    index_enc = bytearray(index_plain)  # copy
    crypt_index_words(index_enc, k2)

    # Header: (flags<<24 | table_size_field) ^ k2
    # For aligned==False, table_size_field = index_plain_size
    # For aligned==True, reader does: size = (field<<11)-8  => field = (size+8)>>11  (must divide cleanly)
    if aligned:
        if (index_plain_size + 8) & 0x7FF:
            raise SystemExit("Index size not 2KB-aligned with +8; cannot set AlignedOffset.")
        table_field = (index_plain_size + 8) >> 11
    else:
        table_field = index_plain_size & 0xFFFFFF
    header_tmp = ((flags & 0xFF) << 24) | (table_field & 0xFFFFFF)
    header_word = header_tmp ^ k2

    # Write out
    with open(out_file, "wb") as out:
        out.write(MAGIC)
        out.write(struct.pack("<I", header_word))
        out.write(index_enc)

        # Write data region with alignment padding if needed
        cur = data_start
        for i, content in enumerate(entries_bytes):
            if aligned:
                pad = (-cur) & 0x7FF
                if pad:
                    out.write(b"\x00" * pad)
                    cur += pad
            out.write(content)
            cur += len(content)

    print(f"Packed {len(files_sorted)} files -> {out_file}")
    print(f"Flags=0x{flags:02X}  Encrypted={bool(flags&0x04)}  Whole={bool(flags&0x10)}  Aligned={bool(flags&0x01)}  Width={width_bytes}")
    print(f"Index={index_plain_size} bytes; data starts at 0x{data_start:X}")

# =========================
#   CLI
# =========================
def main():
    ap = argparse.ArgumentParser(description="Repack Lucifen LPK1 (Shuffle! Essence+).")
    ap.add_argument("input_dir", help="Folder with edited files (names must match those in LPK).")
    ap.add_argument("out_lpk",   help="Output LPK path, e.g. PIC_new.LPK (basename selects keys).")
    ap.add_argument("--clone-from", help="Original LPK to clone flags + prefix (recommended).")
    ap.add_argument("--flags", type=lambda x:int(x,0), help="Override flags byte, e.g. 0x06.")
    ap.add_argument("--whole", action="store_true", help="Force WholeCrypt bit ON.")
    ap.add_argument("--no-whole", action="store_true", help="Force WholeCrypt bit OFF.")
    ap.add_argument("--enc", action="store_true", help="Force Encrypted bit ON.")
    ap.add_argument("--no-enc", action="store_true", help="Force Encrypted bit OFF.")
    ap.add_argument("--width", type=int, choices=[2,4], help="Letter-table offset width (default: cloned or 4).")
    ap.add_argument("--keep-prefix", action="store_true",
                    help="Store the index prefix bytes in each entry (normally you do NOT).")
    ap.add_argument("--no-auto-strip-prefix", action="store_true",
                    help="Do not auto-strip the cloned prefix from input files.")
    args = ap.parse_args()

    whole = True if args.whole else (False if args.no_whole else None)
    enc   = True if args.enc   else (False if args.no_enc   else None)

    repack_lpk(
        input_dir=args.input_dir,
        out_file=args.out_lpk,
        orig_lpk=args.clone_from,
        force_flags=args.flags,
        whole=whole,
        enc=enc,
        width_bytes=args.width,
        keep_prefix=args.keep_prefix,
        auto_strip_prefix=not args.no_auto_strip_prefix
    )

if __name__ == "__main__":
    main()
