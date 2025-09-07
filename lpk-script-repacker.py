# pack_lpk.py
import argparse, os, struct, codecs

# ---------- bit utils ----------
def rotl32(x, r): return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF
def rotr32(x, r): return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF

# ---------- Lucifen default scheme (LPK) ----------
DEFAULT_KEY1 = 0xA5B9AC6B
DEFAULT_KEY2 = 0x9A639DE5
DEFAULT_CONTENT_XOR = 0x5D
DEFAULT_ROTATE_PATTERN = 0x31746285  # for index/entry-key evolution

def derive_keys_from_basename(basename_upper_cp932_bytes, base_key1=DEFAULT_KEY1, base_key2=DEFAULT_KEY2):
    k1, k2 = base_key1, base_key2
    b = basename_upper_cp932_bytes
    for i in range(len(b)):
        k1 ^= b[len(b)-1-i]
        k2 ^= b[i]
        k1 = rotr32(k1, 7)
        k2 = rotl32(k2, 7)
    return k1 & 0xFFFFFFFF, k2 & 0xFFFFFFFF

def encrypt_or_decrypt_index(buf, key2, rotate_pattern=DEFAULT_ROTATE_PATTERN):
    # Symmetric XOR stream keyed by evolving key
    # Operates in-place on 4-byte words
    assert len(buf) % 4 == 0
    pat = rotate_pattern & 0xFFFFFFFF
    out = bytearray(buf)  # copy
    for i in range(0, len(out), 4):
        # uint32 little-endian
        w = struct.unpack_from("<I", out, i)[0]
        w ^= key2
        struct.pack_into("<I", out, i, w & 0xFFFFFFFF)
        # evolve
        pat = rotl32(pat, 4)
        key2 = rotr32(key2, pat & 31)  # rotate by lower 5 bits of pat
    return out

# ---------- Trie builder ----------
class Node:
    __slots__ = ("children", "term")  # children: dict[int->Node], term: entry_index or None
    def __init__(self):
        self.children = {}
        self.term = None

def build_trie(cp932_names_to_index):
    root = Node()
    for name_bytes, idx in cp932_names_to_index:
        cur = root
        for byte in name_bytes:
            cur = cur.children.setdefault(byte, Node())
        cur.term = idx
    return root

def serialize_trie(root, width=4):
    if width not in (2, 4):
        raise ValueError("width must be 2 or 4")
    table = bytearray()

    def write_node(node):
        start = len(table)
        items = sorted(node.children.items(), key=lambda kv: kv[0])
        has_term = node.term is not None
        count = len(items) + (1 if has_term else 0)
        table.append(count & 0xFF)

        edge_positions = []  # (ofs_pos, width, child)
        for b, child in items:
            table.append(b)
            ofs_pos = len(table)
            if width == 4:
                table.extend(b"\x00\x00\x00\x00")
            else:
                table.extend(b"\x00\x00")
            edge_positions.append((ofs_pos, width, child))

        if has_term:
            table.append(0)
            if width == 4:
                table.extend(struct.pack("<I", node.term))
            else:
                if node.term > 0xFFFF:
                    raise ValueError("entry index exceeds 16-bit when width=2")
                table.extend(struct.pack("<H", node.term))

        # Recurse and patch the relative offsets
        for ofs_pos, w, child in edge_positions:
            child_pos = write_node(child)
            base = ofs_pos + (4 if w == 4 else 2)
            rel = child_pos - base
            if w == 4:
                struct.pack_into("<i", table, ofs_pos, rel)
            else:
                if not (0 <= rel <= 0xFFFF):
                    raise ValueError("relative offset does not fit into 16-bit")
                struct.pack_into("<H", table, ofs_pos, rel)

        return start

    write_node(root)
    return bytes(table)

def pack_lpk(output_path, input_dir, base_key1=DEFAULT_KEY1, base_key2=DEFAULT_KEY2):
    # 1) Gather files
    files = []
    for root, _, fnames in os.walk(input_dir):
        for fn in fnames:
            full = os.path.join(root, fn)
            # LPK stores names as relative with backslashes on Windows; we normalize to forward slash for safety
            rel = os.path.relpath(full, input_dir).replace("/", "\\")
            with open(full, "rb") as f:
                data = f.read()
            files.append((rel, data))
    if not files:
        raise SystemExit("No files found to pack.")

    # Deterministic order
    files.sort(key=lambda t: t[0].lower())

    # 2) Assign entry indices
    names_cp932 = []
    for i, (name, _) in enumerate(files):
        try:
            nb = name.encode("cp932", errors="strict")
        except UnicodeEncodeError as e:
            raise SystemExit(f"Filename not encodable in CP932: {name!r} ({e})")
        names_cp932.append((nb, i))

    # 3) Build trie (letter table)
    root = build_trie(names_cp932)
    letter_table = serialize_trie(root, width=4)
    letter_table_len = len(letter_table)

    # 4) Build index (first pass with placeholder entries)
    count = len(files)
    entry_size = 9  # flag(1) + offset(4) + size(4) for uncompressed
    entries_table = bytearray(entry_size * count)
    # initialize flags to 0; offsets/sizes will be patched later

    # index = count(4) | prefix_len(1)=0 | width_flag(1)=1 | letter_table_len(4) | letter_table | entries_table
    index_plain = bytearray()
    index_plain += struct.pack("<I", count)
    index_plain += struct.pack("B", 0)
    index_plain += struct.pack("B", 1)  # 1 => 4-byte offsets
    index_plain += struct.pack("<I", letter_table_len)
    index_plain += letter_table
    entries_start = len(index_plain)
    index_plain += entries_table

    # pad to multiple of 4 for the index crypto
    while len(index_plain) % 4 != 0:
        index_plain.append(0)

    # 5) Derive keys from basename (uppercase, without extension) in CP932
    basename = os.path.splitext(os.path.basename(output_path))[0].upper()
    basename_bytes = basename.encode("cp932", errors="strict")
    key1, key2 = derive_keys_from_basename(basename_bytes, base_key1, base_key2)

    # 6) Compute header + data offsets
    flags = 0x02  # only Flag1 set; no AlignedOffset, no IsEncrypted, no PackedEntries, no WholeCrypt
    index_size_field = len(index_plain)  # not aligned => store plain size (must fit 24 bits)
    if index_size_field >= (1 << 24):
        raise SystemExit("Index too large for 24-bit header field.")
    code = ((flags & 0xFF) << 24) | (index_size_field & 0xFFFFFF)
    header_word = code ^ key2

    data_start = 8 + len(index_plain)
    cur = data_start

    # 7) Patch entries with final offsets/sizes
    patched = bytearray(index_plain)
    for i, (name, data) in enumerate(files):
        # write flag=0, offset, size
        pos = entries_start + i * entry_size
        struct.pack_into("B", patched, pos, 0)
        struct.pack_into("<I", patched, pos + 1, cur)
        struct.pack_into("<I", patched, pos + 5, len(data))
        cur += len(data)

    # 8) Encrypt index
    index_encrypted = encrypt_or_decrypt_index(patched, key2)

    # 9) Write archive
    with open(output_path, "wb") as out:
        out.write(b"LPK1")
        out.write(struct.pack("<I", header_word))
        out.write(index_encrypted)
        # file payloads
        for _, data in files:
            out.write(data)

    print(f"Packed {count} entries -> {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Simple Lucifen LPK packer (no compression, no content encryption).")
    ap.add_argument("output", help="Output .lpk file")
    ap.add_argument("input_dir", help="Folder to pack")
    ap.add_argument("--base-key1", type=lambda x:int(x,0), default=DEFAULT_KEY1, help="Base key1 (uint32, hex or int)")
    ap.add_argument("--base-key2", type=lambda x:int(x,0), default=DEFAULT_KEY2, help="Base key2 (uint32, hex or int)")
    args = ap.parse_args()
    pack_lpk(args.output, args.input_dir, args.base_key1, args.base_key2)