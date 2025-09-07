#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, os, struct
from typing import Tuple
from PIL import Image  # pip install pillow

# Valid ELG signatures (little-endian uint32) -> b'ELG\x01', b'ELG\x08', b'ELG\x18', b'ELG\x20', b'ELG\x02'
ELG_SIGNATURES = {0x01474C45, 0x08474C45, 0x18474C45, 0x20474C45, 0x02474C45}

class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.p = 0
        self.w = 0
        self.h = 0
        self.bpp = 0
        self.type = 0
        self.header_size = 0
        self.offset_x = 0
        self.offset_y = 0

    def _u8(self):  v = self.data[self.p]; self.p += 1; return v
    def _u16(self): v, = struct.unpack_from('<H', self.data, self.p); self.p += 2; return v
    def _s16(self): v, = struct.unpack_from('<h', self.data, self.p); self.p += 2; return v
    def _u32(self): v, = struct.unpack_from('<I', self.data, self.p); self.p += 4; return v
    def seek(self, off, whence=os.SEEK_SET):
        if whence == os.SEEK_SET: self.p = off
        elif whence == os.SEEK_CUR: self.p += off
        elif whence == os.SEEK_END: self.p = len(self.data) + off

    def read_header(self):
        if len(self.data) < 8:
            raise ValueError("ELG too short")
        sig, = struct.unpack_from('<I', self.data, 0)
        if sig not in ELG_SIGNATURES:
            raise ValueError("Not an ELG image")
        # The format stores type/bpp after byte 3.
        self.p = 3
        b = self._u8()
        self.type = b
        self.offset_x = self.offset_y = 0
        self.header_size = 8

        if self.type == 2:
            self.bpp = self._u8()
            self.header_size = 13
        elif self.type == 1:
            self.bpp = self._u8()
            self.offset_x = self._s16()
            self.offset_y = self._s16()
            self.header_size = 13
        else:
            # Type 0 path: b was actually bpp
            self.bpp = b
            self.type = 0

        # Common tail: width/height
        self.w = self._u16()
        self.h = self._u16()

        if self.type == 2:
            self.offset_x = self._s16()
            self.offset_y = self._s16()

        if self.bpp not in (8, 24, 32):
            raise ValueError(f"Unsupported ELG bpp={self.bpp}")

    def _unpack_indexed_stream(self, out: bytearray):
        """Shared RLE/LZ unpacker for 8bpp pixel data and 0x400-byte palette."""
        dst = 0
        L = len(out)
        while True:
            flags = self._u8()
            if flags == 0xFF or dst >= L:
                break
            if (flags & 0xC0) == 0x00:
                # Literal bytes
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 33
                else:
                    count = (flags & 0x1F) + 1
                out[dst:dst+count] = self.data[self.p:self.p+count]
                self.p += count; dst += count
            elif (flags & 0xC0) == 0x40:
                # Run of a single value
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 35
                else:
                    count = (flags & 0x1F) + 3
                v = self._u8()
                out[dst:dst+count] = bytes([v]) * count
                dst += count
            else:
                # Back-reference copy
                if (flags & 0xC0) == 0x80:
                    if (flags & 0x30) == 0x00:
                        count = (flags & 0x0F) + 2
                        pos = self._u8() + 2
                    elif (flags & 0x30) == 0x10:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = self._u8() + 4
                    elif (flags & 0x30) == 0x20:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = 3
                    else:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = 4
                else:
                    if (flags & 0x20) != 0:
                        pos = (flags & 0x1F) + 2
                        count = 2
                    else:
                        pos = (flags & 0x1F) + 1
                        count = 1
                src = dst - pos
                # overlapped copy
                for _ in range(count):
                    out[dst] = out[src]
                    dst += 1; src += 1

    def _unpack_rgb(self, out: bytearray):
        dst = 0
        L = len(out)
        while True:
            flags = self._u8()
            if flags == 0xFF or dst >= L:
                break
            if (flags & 0xC0) == 0x00:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 33
                else:
                    count = (flags & 0x1F) + 1
                for _ in range(count):
                    out[dst]   = self._u8()  # B
                    out[dst+1] = self._u8()  # G
                    out[dst+2] = self._u8()  # R
                    dst += 3
            elif (flags & 0xC0) == 0x40:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 34
                else:
                    count = (flags & 0x1F) + 2
                b = self._u8(); g = self._u8(); r = self._u8()
                for _ in range(count):
                    out[dst:dst+3] = bytes((b,g,r)); dst += 3
            elif (flags & 0xC0) == 0x80:
                if (flags & 0x30) == 0x00:
                    count = (flags & 0x0F) + 1
                    pos = self._u8() + 2
                elif (flags & 0x30) == 0x10:
                    pos = ((flags & 0x0F) << 8) + self._u8() + 2
                    count = self._u8() + 1
                elif (flags & 0x30) == 0x20:
                    tmp = self._u8()
                    pos = ((((flags & 0x0F) << 8) + tmp) << 8) + self._u8() + 4098
                    count = self._u8() + 1
                else:
                    if (flags & 0x08) != 0:
                        pos = ((flags & 0x07) << 8) + self._u8() + 10
                    else:
                        pos = (flags & 0x07) + 2
                    count = 1
                src = dst - 3*pos
                # overlapped copy
                for _ in range(count*3):
                    out[dst] = out[src]; dst += 1; src += 1
            else:
                # Neighbor copy (spatial)
                if (flags & 0x30) == 0x00:
                    if (flags & 0x0C) == 0x00:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = 0
                    elif (flags & 0x0C) == 0x04:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = -1
                    elif (flags & 0x0C) == 0x08:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = 1
                    else:
                        pos = ((flags & 0x03) << 8) + self._u8() + 2058
                        src = dst - 3*pos
                        out[dst:dst+3] = out[src:src+3]; dst += 3
                        continue
                elif (flags & 0x30) == 0x10:
                    y = (flags & 0x0F) + 1; x = 0
                elif (flags & 0x30) == 0x20:
                    y = (flags & 0x0F) + 1; x = -1
                else:
                    y = (flags & 0x0F) + 1; x = 1
                src = dst + (x - self.w * y) * 3
                out[dst:dst+3] = out[src:src+3]; dst += 3

    def _unpack_rgba(self, out_bgra: bytearray):
        dst = 0
        L = len(out_bgra)
        # RGB pass (alpha set to 0xFF initially)
        while True:
            flags = self._u8()
            if flags == 0xFF or dst >= L:
                break
            if (flags & 0xC0) == 0x00:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 33
                else:
                    count = (flags & 0x1F) + 1
                for _ in range(count):
                    out_bgra[dst]   = self._u8()  # B
                    out_bgra[dst+1] = self._u8()  # G
                    out_bgra[dst+2] = self._u8()  # R
                    out_bgra[dst+3] = 0xFF
                    dst += 4
            elif (flags & 0xC0) == 0x40:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 34
                else:
                    count = (flags & 0x1F) + 2
                b = self._u8(); g = self._u8(); r = self._u8()
                for _ in range(count):
                    out_bgra[dst:dst+4] = bytes((b,g,r,0xFF)); dst += 4
            elif (flags & 0xC0) == 0x80:
                if (flags & 0x30) == 0x00:
                    count = (flags & 0x0F) + 1
                    pos = self._u8() + 2
                elif (flags & 0x30) == 0x10:
                    pos = ((flags & 0x0F) << 8) + self._u8() + 2
                    count = self._u8() + 1
                elif (flags & 0x30) == 0x20:
                    tmp = self._u8()
                    pos = ((((flags & 0x0F) << 8) + tmp) << 8) + self._u8() + 4098
                    count = self._u8() + 1
                else:
                    if (flags & 0x08) != 0:
                        pos = ((flags & 0x07) << 8) + self._u8() + 10
                    else:
                        pos = (flags & 0x07) + 2
                    count = 1
                src = dst - 4*pos
                for _ in range(count*4):
                    out_bgra[dst] = out_bgra[src]; dst += 1; src += 1
            else:
                # Neighbor copy (spatial)
                if (flags & 0x30) == 0x00:
                    if (flags & 0x0C) == 0x00:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = 0
                    elif (flags & 0x0C) == 0x04:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = -1
                    elif (flags & 0x0C) == 0x08:
                        y = ((flags & 0x03) << 8) + self._u8() + 16; x = 1
                    else:
                        pos = ((flags & 0x03) << 8) + self._u8() + 2058
                        src = dst - 4*pos
                        out_bgra[dst:dst+4] = out_bgra[src:src+4]; dst += 4
                        continue
                elif (flags & 0x30) == 0x10:
                    y = (flags & 0x0F) + 1; x = 0
                elif (flags & 0x30) == 0x20:
                    y = (flags & 0x0F) + 1; x = -1
                else:
                    y = (flags & 0x0F) + 1; x = 1
                src = dst + (x - self.w * y) * 4
                out_bgra[dst:dst+4] = out_bgra[src:src+4]; dst += 4

    def _unpack_alpha(self, out_bgra: bytearray):
        dst = 3  # start at alpha byte of first pixel (BGRA)
        L = len(out_bgra)
        while True:
            flags = self._u8()
            if flags == 0xFF or dst >= L:
                break
            if (flags & 0xC0) == 0x00:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 33
                else:
                    count = (flags & 0x1F) + 1
                for _ in range(count):
                    out_bgra[dst] = self._u8()
                    dst += 4
            elif (flags & 0xC0) == 0x40:
                if (flags & 0x20) != 0:
                    count = ((flags & 0x1F) << 8) + self._u8() + 35
                else:
                    count = (flags & 0x1F) + 3
                a = self._u8()
                for _ in range(count):
                    out_bgra[dst] = a; dst += 4
            else:
                if (flags & 0xC0) == 0x80:
                    if (flags & 0x30) == 0x00:
                        count = (flags & 0x0F) + 2
                        pos = self._u8() + 2
                    elif (flags & 0x30) == 0x10:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = self._u8() + 4
                    elif (flags & 0x30) == 0x20:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = 3
                    else:
                        pos = ((flags & 0x0F) << 8) + self._u8() + 3
                        count = 4
                else:
                    if (flags & 0x20) != 0:
                        pos = (flags & 0x1F) + 2
                        count = 2
                    else:
                        pos = (flags & 0x1F) + 1
                        count = 1
                src = dst - 4*pos
                for _ in range(count):
                    out_bgra[dst] = out_bgra[src]
                    src += 4; dst += 4

    def decode(self) -> Image.Image:
        self.read_header()
        # Move to pixel stream start
        self.p = self.header_size

        # Type 2: skip chunk table (each record: 1 byte nonzero, then int32 size including that int32)
        if self.type == 2:
            while True:
                marker = self._u8()
                if marker == 0:
                    break
                size = self._u32()
                if size < 4:
                    raise ValueError("ELG: invalid chunk size")
                self.seek(size - 4, os.SEEK_CUR)

        if self.bpp == 8:
            # palette first (0x400 bytes via same unpacker), then indices
            pal_bytes = bytearray(0x400)
            self._unpack_indexed_stream(pal_bytes)
            # Palette data stored as BGRA; we want a flat [R,G,B]*256 list
            palette = []
            for i in range(256):
                b = pal_bytes[i*4 + 0]
                g = pal_bytes[i*4 + 1]
                r = pal_bytes[i*4 + 2]
                palette.extend((r, g, b))
            pix = bytearray(self.w * self.h)
            self._unpack_indexed_stream(pix)
            im = Image.frombytes("P", (self.w, self.h), bytes(pix))
            im.putpalette(palette)
            return im

        elif self.bpp == 24:
            buf = bytearray(self.w * self.h * 3)  # BGR
            self._unpack_rgb(buf)
            # PIL can ingest raw BGR directly
            return Image.frombytes("RGB", (self.w, self.h), bytes(buf), "raw", "BGR")

        else:  # 32 bpp BGRA with separate alpha stream
            buf = bytearray(self.w * self.h * 4)
            self._unpack_rgba(buf)
            self._unpack_alpha(buf)
            # Convert BGRA->RGBA for Pillow
            # Fast channel swap:
            rgba = bytearray(buf)  # copy
            rgba[0::4], rgba[2::4] = buf[2::4], buf[0::4]
            return Image.frombytes("RGBA", (self.w, self.h), bytes(rgba))

def convert_one(src: str, dst: str):
    with open(src, "rb") as f:
        data = f.read()
    img = Reader(data).decode()
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    img.save(dst)

def batch_convert(src_path: str, dst_path: str):
    if os.path.isfile(src_path):
        if os.path.isdir(dst_path):
            base = os.path.splitext(os.path.basename(src_path))[0] + ".png"
            convert_one(src_path, os.path.join(dst_path, base))
        else:
            convert_one(src_path, dst_path)
    else:
        # src_path is a folder
        os.makedirs(dst_path, exist_ok=True)
        for root, _, files in os.walk(src_path):
            for fn in files:
                if fn.lower().endswith(".elg"):
                    in_fp = os.path.join(root, fn)
                    rel = os.path.relpath(in_fp, src_path)
                    out_fp = os.path.join(dst_path, os.path.splitext(rel)[0] + ".png")
                    os.makedirs(os.path.dirname(out_fp), exist_ok=True)
                    convert_one(in_fp, out_fp)

def main():
    ap = argparse.ArgumentParser(description="Convert Lucifen ELG images to PNG")
    ap.add_argument("input", help="ELG file or a folder containing .elg files")
    ap.add_argument("output", help="Output PNG path (for single file) or a folder for batch")
    args = ap.parse_args()
    batch_convert(args.input, args.output)
    print("Done.")

if __name__ == "__main__":
    main()
