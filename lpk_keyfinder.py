#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucifen LPK aux-key finder + validator

Usage examples:
  python lpk_keyfinder.py game.lpk --scan gameinit.sob navel03.sob
  python lpk_keyfinder.py game.lpk --scan ./game_dir --out keys.json
  python lpk_keyfinder.py game.lpk --scan main.exe data.pak --stride 4 --max-candidates 10

This scans provided files/dirs for 8-byte sequences that could be (aux1, aux2).
For each candidate pair, it tries to decrypt the LPK index and validates its structure.
Top candidates are printed and (optionally) saved to a keys.json mapping.
"""

import os
import sys
import json
import mmap
import argparse
import struct
from typing import Optional, Tuple, List, Dict

# ---------------- Bit helpers ----------------
def rotl32(v: int, c: int) -> int:
    c &= 31
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF

def rotr32(v: int, c: int) -> int:
    c &= 31
    return ((v >> c) | (v << (32 - c))) & 0xFFFFFFFF

def rotr8(v: int, c: int) -> int:
    c &= 7
    return ((v >> c) | ((v << (8 - c)) & 0xFF)) & 0xFF

# ---------------- Lucifen constants ----------------
BASE_KEY1 = 0xA5B9AC6B
BASE_KEY2 = 0x9A639DE5
ROTATE_PATTERN = 0x31746285
CONTENT_XOR = 0x5D

ALIGNED_OFFSET = 0x01
FLAG1          = 0x02
IS_ENCRYPTED1  = 0x04
IS_COMPRESSED  = 0x08
IS_ENCRYPTED2  = 0x10

# ---------------- Encoding helpers ----------------
def sjis_basename_bytes(lpk_path: str) -> bytes:
    stem = os.path.splitext(os.path.basename(lpk_path))[0]
    return stem.encode("cp932", errors="ignore")

# ---------------- Key derivation ----------------
def derive_base_keys(lpk_path: str) -> Tuple[int, int]:
    k1, k2 = BASE_KEY1, BASE_KEY2
    name = sjis_basename_bytes(lpk_path)
    for i in range(len(name)):
        b = name[i]
        e = name[len(name) - 1 - i]
        k1 ^= e
        k2 ^= b
        k1 = rotr32(k1, 7)
        k2 = rotl32(k2, 7)
    return k1, k2

def apply_aux(k1: int, k2: int, aux1: int, aux2: int) -> Tuple[int, int]:
    return (k1 ^ aux1, k2 ^ aux2)

# ---------------- Decrypt routines ----------------
def decrypt_table_inplace(buf: bytearray, key2: int) -> None:
    """Decrypts the LPK index/table in-place (u32-wise)."""
    rp = ROTATE_PATTERN
    n = len(buf) // 4
    u = list(struct.unpack("<%dI" % n, buf[:n*4]))
    for i in range(n):
        u[i] ^= key2
        rp = rotl32(rp, 4)
        key2 = rotr32(key2, rp)
    buf[:n*4] = struct.pack("<%dI" % n, *u)

# ---------------- Index sanity & traversal ----------------
def is_plausible_printable(byte_val: int) -> bool:
    """Rough check for filename characters in CP932/ASCII (allow '/', '_', '-', '.', digits, letters)."""
    if byte_val in (47, 92, 95, 45, 46):  # / \ _ - .
        return True
    if 48 <= byte_val <= 57:   # 0-9
        return True
    if 65 <= byte_val <= 90:   # A-Z
        return True
    if 97 <= byte_val <= 122:  # a-z
        return True
    # allow a few common CP932 punctuation bytes
    if byte_val in (32, 35, 36, 40, 41, 91, 93):  # space # $ ( ) [ ]
        return True
    return False

def parse_index_header(index: bytes) -> Optional[Tuple[int, int, int, int, int]]:
    """Parse minimal header fields; return (file_count, prefix_len, index_width, letter_table_len, entries_off)."""
    if len(index) < 12:
        return None
    pos = 0
    file_count = struct.unpack_from("<I", index, pos)[0]; pos += 4
    if file_count <= 0 or file_count > 1_000_000:
        return None
    prefix_len = index[pos]; pos += 1
    if prefix_len > 200:  # generous
        return None
    if pos + prefix_len + 5 > len(index):
        return None
    pos += prefix_len  # skip prefix
    index_width = 4 if index[pos] != 0 else 2; pos += 1
    letter_table_len = struct.unpack_from("<I", index, pos)[0]; pos += 4
    if pos + letter_table_len > len(index):
        return None
    entries_off = pos + letter_table_len
    return (file_count, prefix_len, index_width, letter_table_len, entries_off)

def light_traverse_score(index: bytes, entries_off: int, entry_size: int, index_width: int, sample_limit: int = 256) -> int:
    """
    Lightly traverse the letter table (without dereferencing entries) to score plausibility.
    We just verify node structure and plausible letters. Returns a score.
    """
    score = 0
    stack = [ (entries_off - (4 + 1 + 1 + 4), 0) ]  # not used, but keep shape; we'll scan the letter area directly
    # Instead of full traverse, read the letter area (roughly) and count plausible letters.
    # The letter area starts after the 4+1(+prefix)+1+4 header; we don't have exact bounds for each node,
    # but counting plausible letters helps reduce false positives.
    # We'll read up to sample_limit bytes of what should be "letters" and child offsets.
    # Heuristic: many letters should be printable-ish.
    sample = index[entries_off - entry_size : entries_off] if entries_off >= entry_size else index[:entries_off]
    # add a small bias for printable characters in the header area
    score += sum(1 for b in sample if is_plausible_printable(b))
    return score

def validate_index_structure(index: bytes, flags: int) -> Tuple[bool, int]:
    hdr = parse_index_header(index)
    if not hdr:
        return (False, 0)
    file_count, prefix_len, index_width, letter_table_len, entries_off = hdr
    entry_size = 13 if (flags & IS_COMPRESSED) else 9
    if entries_off + entry_size > len(index):
        return (False, 0)
    # Heuristic: if compressed flag set, there must be space for at least one 13-byte entry.
    if (flags & IS_COMPRESSED) and (len(index) - entries_off) < 13:
        return (False, 0)
    # Light plausibility score
    score = 10  # base score for passing header checks
    score += light_traverse_score(index, entries_off, entry_size, index_width)
    return (True, score)

# ---------------- Candidate search ----------------
def iter_candidate_pairs_from_file(path: str, stride: int = 4, max_read_bytes: Optional[int] = None):
    try:
        size = os.path.getsize(path)
        limit = size if max_read_bytes is None else min(size, max_read_bytes)
        with open(path, "rb") as f:
            data = f.read(limit)
        # slide a window; emit (aux1, aux2) as 2 consecutive u32
        end = len(data) - 7
        i = 0
        while i <= end:
            a1 = struct.unpack_from("<I", data, i)[0]
            a2 = struct.unpack_from("<I", data, i+4)[0]
            yield (a1, a2, path, i, False)
            yield (a2, a1, path, i, True)  # swapped
            i += stride
    except Exception:
        return

def collect_files_to_scan(inputs: List[str]) -> List[str]:
    out = []
    for p in inputs:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for name in files:
                    fp = os.path.join(root, name)
                    out.append(fp)
        else:
            out.append(p)
    # de-dup
    seen = set()
    res = []
    for f in out:
        if f not in seen:
            seen.add(f)
            res.append(f)
    return res

# ---------------- Main search ----------------
def find_aux_keys_for_lpk(lpk_path: str,
                          scan_inputs: List[str],
                          stride: int = 4,
                          max_candidates: int = 20,
                          max_read_bytes: Optional[int] = None) -> List[Dict]:
    base_k1, base_k2 = derive_base_keys(lpk_path)

    with open(lpk_path, "rb") as f:
        lpk_mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        lpk_size = lpk_mm.size()
        # header (unknown k2 yet) is tested per candidate

        results = []
        seen_pairs = set()

        files = collect_files_to_scan(scan_inputs)
        for file_path in files:
            for a1, a2, src, off, swapped in iter_candidate_pairs_from_file(file_path, stride=stride, max_read_bytes=max_read_bytes):
                pair_key = (a1, a2)
                if pair_key in seen_pairs:
                    continue
                # combine into working keys
                k1, k2 = apply_aux(base_k1, base_k2, a1, a2)
                # try decrypt header with k2
                try:
                    header = struct.unpack_from("<I", lpk_mm, 4)[0] ^ k2
                except Exception:
                    continue
                flags = (header >> 24) & 0xFF
                index_size = header & 0xFFFFFF
                if flags & ALIGNED_OFFSET:
                    index_size = (index_size << 11) - 8
                # quick sanity
                if (flags & FLAG1) == 0:
                    continue
                if index_size < 12 or 8 + index_size > lpk_size:
                    continue
                # decrypt table
                table = bytearray(lpk_mm[8:8+index_size])
                decrypt_table_inplace(table, k2)
                ok, score = validate_index_structure(table, flags)
                if ok:
                    # stronger bonus: check that after header, some bytes look printable
                    bonus = sum(1 for b in table[:64] if is_plausible_printable(b))
                    score += bonus
                    results.append({
                        "aux1": a1, "aux2": a2,
                        "final_k1": k1, "final_k2": k2,
                        "flags": flags,
                        "score": score,
                        "source": src, "offset": off, "swapped": swapped
                    })
                    seen_pairs.add(pair_key)
                    # keep list bounded
                    results.sort(key=lambda r: r["score"], reverse=True)
                    if len(results) > max_candidates:
                        results = results[:max_candidates]
        lpk_mm.close()
        return results

def to_hex32(x: int) -> str:
    return f"0x{x:08X}"

def write_keys_json(out_path: str, lpk_path: str, best: Dict) -> None:
    stem = os.path.splitext(os.path.basename(lpk_path))[0].lower()
    js = {stem: {"key1": to_hex32(best["aux1"]), "key2": to_hex32(best["aux2"])}}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(js, f, indent=2, ensure_ascii=False)

def main():
    ap = argparse.ArgumentParser(description="Find plausible Lucifen LPK aux keys by scanning nearby files (SOB/EXE/etc).")
    ap.add_argument("lpk", help="Path to .lpk file")
    ap.add_argument("--scan", nargs="+", required=True, help="Files or directories to scan for aux-key pairs")
    ap.add_argument("--stride", type=int, default=4, help="Byte step while scanning (use 1 for exhaustive; default 4)")
    ap.add_argument("--max-candidates", type=int, default=20, help="Max candidates to keep/show")
    ap.add_argument("--max-read-bytes", type=int, default=None, help="Limit bytes read per file (e.g., 16777216 for 16MB)")
    ap.add_argument("--out", help="Optional path to write keys.json for the top candidate")
    args = ap.parse_args()

    results = find_aux_keys_for_lpk(args.lpk, args.scan, stride=args.stride,
                                    max_candidates=args.max_candidates,
                                    max_read_bytes=args.max_read_bytes)

    if not results:
        print("No plausible aux keys found.")
        sys.exit(2)

    print("\nTop candidates (best first):")
    for i, r in enumerate(results, 1):
        print(f"{i:2d}. aux=({to_hex32(r['aux1'])}, {to_hex32(r['aux2'])})  "
              f"final=({to_hex32(r['final_k1'])}, {to_hex32(r['final_k2'])})  "
              f"flags=0x{r['flags']:02X}  score={r['score']}  "
              f"src={os.path.basename(r['source'])} off=0x{r['offset']:X}{' [swapped]' if r['swapped'] else ''}")

    if args.out:
        write_keys_json(args.out, args.lpk, results[0])
        print(f"\nSaved best candidate to: {args.out}")

if __name__ == "__main__":
    main()
