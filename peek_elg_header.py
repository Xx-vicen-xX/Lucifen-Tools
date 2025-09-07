# peek_elg_header.py (accepts all ELG variants)
import sys, struct
ELG_SIGS = {0x01474C45, 0x08474C45, 0x18474C45, 0x20474C45, 0x02474C45}
with open(sys.argv[1], "rb") as f:
    h = f.read(32)
if len(h) < 16:
    raise SystemExit("too short")
sig, = struct.unpack_from("<I", h, 0)
if sig not in ELG_SIGS:
    raise SystemExit("not ELG")
t = h[3]; p = 4
if t == 2:
    bpp = h[p]; p += 1
elif t == 1:
    bpp = h[p]; p += 1; p += 4  # skip offsets
else:
    bpp = t
w, hgt = struct.unpack_from("<HH", h, p)
print(f"type={t} bpp={bpp} size={w}x{hgt}")
