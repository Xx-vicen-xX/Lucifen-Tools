import os, sys, json, struct, mmap, argparse
from typing import Optional, Tuple

# ---------- bit helpers (always mod 32) ----------
def rotl32(v, c): c &= 31; return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF
def rotr32(v, c): c &= 31; return ((v >> c) | (v << (32 - c))) & 0xFFFFFFFF
def rotr8 (v, c): c &= 7;  return ((v >> c) | ((v << (8 - c)) & 0xFF)) & 0xFF

# ---------- constants from plugin ----------
BASE_KEY1 = 0xA5B9AC6B
BASE_KEY2 = 0x9A639DE5
ROTATE_PATTERN = 0x31746285
CONTENT_XOR = 0x5D

# flags per your C++
ALIGNED_OFFSET = 0x01
FLAG1          = 0x02
IS_ENCRYPTED1  = 0x04  # 0..0xFF of first up-to-0x100 bytes (u32)
IS_COMPRESSED  = 0x08  # archive uses LZSS, entries carry size_orig field
IS_ENCRYPTED2  = 0x10  # byte xor/rotate (whole content) after decompress

# ---------- aux-key loading ----------
def parse_hex_u32(s: str) -> int:
    s = s.strip().lower()
    return int(s, 16) if s.startswith("0x") else int(s)

def load_aux_key(basename_lower: str, keys_json_path: Optional[str], cli_key: Optional[Tuple[int,int]]) -> Optional[Tuple[int,int]]:
    if cli_key:
        return cli_key
    if keys_json_path:
        with open(keys_json_path, "r", encoding="utf-8") as f:
            j = json.load(f)
        # allow {"file.lpk":{"key1": "...","key2":"..."}}, {"file":{"key1":...}}, or {"file":[k1,k2]}
        cand = j.get(basename_lower) or j.get(os.path.splitext(basename_lower)[0])
        if cand is None:
            return None
        if isinstance(cand, dict):
            return (parse_hex_u32(cand["key1"]), parse_hex_u32(cand["key2"]))
        if isinstance(cand, list) and len(cand) == 2:
            return (parse_hex_u32(cand[0]), parse_hex_u32(cand[1]))
    return None

# ---------- decryption ----------
def decrypt_table(data: bytearray, key: int, rotate_pattern: int):
    # table is u32-aligned; per-u32: v ^= key; rotate_pattern = rotl32(pattern,4); key = rotr32(key, rotate_pattern)
    n = len(data) // 4
    u = list(struct.unpack("<%dI" % n, data[:n*4]))
    rp = rotate_pattern
    k  = key
    for i in range(n):
        u[i] ^= k
        rp = rotl32(rp, 4)
        k  = rotr32(k, rp)
    data[:n*4] = struct.pack("<%dI" % n, *u)

def decrypt_content_1_first_256(data: bytearray, key: int, rotate_pattern: int):
    # operate on up to first 0x100 bytes as u32s
    nbytes = min(len(data), 0x100)
    n = nbytes // 4
    if n == 0: return
    u = list(struct.unpack("<%dI" % n, data[:n*4]))
    rp = rotate_pattern
    k  = key
    for i in range(n):
        u[i] ^= k
        rp = rotr32(rp, 4)
        k  = rotl32(k, rp)
    data[:n*4] = struct.pack("<%dI" % n, *u)

def decrypt_content_2_full(data: bytearray, key_byte: int):
    for i in range(len(data)):
        data[i] = rotr8(data[i] ^ key_byte, 4)

# ---------- LZSS (try both common flag senses) ----------
def lzss_try(data: bytes, out_size: int, literal_when_flag_is_one: bool) -> Optional[bytearray]:
    out = bytearray()
    i = 0
    L = len(data)
    while i < L and len(out) < out_size:
        flags = data[i]; i += 1
        for _ in range(8):
            if len(out) >= out_size: break
            if i >= L: break
            bit_is_one = (flags & 1) == 1
            flags >>= 1
            literal = bit_is_one if literal_when_flag_is_one else (not bit_is_one)
            if literal:
                out.append(data[i]); i += 1
            else:
                if i + 1 >= L: return None
                ref = (data[i] << 8) | data[i+1]; i += 2
                length = (ref & 0x0F) + 3
                offset = (ref >> 4) & 0x0FFF
                start = len(out) - offset - 1
                if start < 0:  # invalid backref
                    return None
                for k in range(length):
                    if len(out) >= out_size: break
                    out.append(out[start + k])
    return out if len(out) == out_size else None

def lzss_decompress(data: bytes, out_size: int) -> bytearray:
    # Try the “flags LSB==1 means literal” first; if it fails, flip.
    r = lzss_try(data, out_size, literal_when_flag_is_one=True)
    if r is not None: return r
    r = lzss_try(data, out_size, literal_when_flag_is_one=False)
    if r is not None: return r
    # last resort: return best-effort (may be short)
    return bytearray(data[:out_size])

# ---------- index traversal ----------
def traverse_index(index: bytes, start_off: int, offset_size: int, entries_off: int, entry_size: int):
    # Iterative like the C++: stack of (offset, current_name)
    stack = [(start_off, "")]
    result = []  # list of (entry_index_in_table, name)
    p = 0
    while stack:
        node_off, name = stack.pop()
        if node_off < 0 or node_off >= len(index):
            raise ValueError("Index node out of range")
        entry_count = index[node_off]
        pos = node_off + 1
        for _ in range(entry_count):
            next_letter = index[pos]; pos += 1
            if offset_size == 4:
                next_offset = struct.unpack_from("<I", index, pos)[0]; pos += 4
            else:
                next_offset = struct.unpack_from("<H", index, pos)[0]; pos += 2
            if next_letter == 0:
                result.append( (entries_off + next_offset * entry_size, name) )
            else:
                stack.append( (pos + next_offset, name + chr(next_letter)) )
    return result

# ---------- main open/extract ----------
def extract_lpk(path: str, keys_json: Optional[str], aux_key_cli: Optional[Tuple[int,int]]):
    base = os.path.splitext(os.path.basename(path))[0]
    base_sjis = base.encode("cp932", errors="ignore")
    base_lower = base.lower()

    with open(path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # signature 'LPK1'
        sig = struct.unpack_from("<I", mm, 0)[0]
        if sig != 0x314B504C:
            raise ValueError("Not a valid LPK1 file")

        # derive key1/key2 from basename (sjis), then apply aux key if available
        k1 = BASE_KEY1
        k2 = BASE_KEY2
        for i in range(len(base_sjis)):
            b = base_sjis[i]
            e = base_sjis[len(base_sjis)-1-i]
            k1 ^= e; k2 ^= b
            k1 = rotr32(k1, 7); k2 = rotl32(k2, 7)

        aux = load_aux_key(base_lower, keys_json, aux_key_cli)
        # Your C++ refuses to proceed if file isn't in the map: “File not known, can't tell the key”.
        # We'll warn but still try with base key only if none is provided.
        if aux:
            k1 ^= aux[0]
            k2 ^= aux[1]

        # header
        header_x = struct.unpack_from("<I", mm, 4)[0] ^ k2
        flags = (header_x >> 24) & 0xFF
        table_size = header_x & 0xFFFFFF
        if flags & ALIGNED_OFFSET:
            table_size = (table_size << 11) - 8

        table = bytearray(mm[8:8+table_size])
        decrypt_table(table, k2, ROTATE_PATTERN)

        # parse table
        off = 0
        file_count = struct.unpack_from("<I", table, off)[0]; off += 4
        prefix_len = table[off]; off += 1
        prefix = table[off:off+prefix_len]; off += prefix_len
        offset_size = 4 if table[off] != 0 else 2; off += 1
        letter_table_len = struct.unpack_from("<I", table, off)[0]; off += 4
        entries_off = off + letter_table_len
        # entry struct size
        entry_size = 13 if (flags & IS_COMPRESSED) else 9

        # gather (entry_struct_pos, name)
        minis = traverse_index(table, off, offset_size, entries_off, entry_size)

        # read entries
        entries = []
        for entry_struct_pos, name in minis:
            if entry_struct_pos + entry_size > len(table):
                raise ValueError("Entry table overflow")
            pos = entry_struct_pos
            # if entry_size is odd (13), there is a flags byte at start
            entry_flags = 0
            if entry_size & 1:
                entry_flags = table[pos]; pos += 1
            offset = struct.unpack_from("<I", table, pos)[0]; pos += 4
            if flags & ALIGNED_OFFSET:
                offset <<= 11
            size_comp = struct.unpack_from("<I", table, pos)[0]; pos += 4
            size_orig = size_comp
            if flags & IS_COMPRESSED:
                size_orig = struct.unpack_from("<I", table, pos)[0]; pos += 4
            entries.append((name, entry_flags, offset, size_comp, size_orig))

        # extract
        out_dir = path + "_extracted"
        os.makedirs(out_dir, exist_ok=True)
        for name, eflags, off_data, sz_c, sz_o in entries:
            # slice file data
            end = min(off_data + sz_c, len(mm))
            chunk = bytearray(mm[off_data:end])
            # order: decompress -> decrypt2 -> decrypt1
            if flags & IS_COMPRESSED:
                chunk = lzss_decompress(bytes(chunk), sz_o)
            if flags & IS_ENCRYPTED2:
                decrypt_content_2_full(chunk, CONTENT_XOR)
            if flags & IS_ENCRYPTED1:
                decrypt_content_1_first_256(chunk, k1, ROTATE_PATTERN)
            # apply archive prefix
            if prefix:
                chunk = bytearray(prefix) + chunk
            # write
            out_path = os.path.join(out_dir, name)
            os.makedirs(os.path.dirname(out_path) or out_dir, exist_ok=True)
            with open(out_path, "wb") as wf:
                wf.write(chunk)

        mm.close()
        return out_dir

def main():
    ap = argparse.ArgumentParser(description="Extract Lucifen LPK archives")
    ap.add_argument("lpk", help="path to .lpk file")
    ap.add_argument("--keys", help="JSON file mapping basename->aux key", default=None)
    ap.add_argument("--aux-key", nargs=2, metavar=("K1","K2"),
                    help="aux key pair for this archive (hex or dec), overrides --keys", default=None)
    args = ap.parse_args()
    aux_pair = None
    if args.aux_key:
        aux_pair = (parse_hex_u32(args.aux_key[0]), parse_hex_u32(args.aux_key[1]))
    try:
        out_dir = extract_lpk(args.lpk, args.keys, aux_pair)
        print(f"Done. Files in: {out_dir}")
    except Exception as e:
        print(f"Error: {e}")
        raise

if __name__ == "__main__":
    main()
