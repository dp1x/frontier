"""Cleanroom Boolean strict UTF-8 validator derived from Unicode 17.0.0
Table 3-7 (Well-Formed UTF-8 Byte Sequences). Not copied from any tested
library.
"""
from __future__ import annotations


def is_valid_utf8(data: bytes) -> bool:
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b <= 0x7F:
            i += 1
            continue
        if 0xC2 <= b <= 0xDF:
            if i + 1 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0xBF):
                return False
            i += 2
            continue
        if b == 0xE0:
            if i + 2 >= n:
                return False
            if not (0xA0 <= data[i + 1] <= 0xBF):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            i += 3
            continue
        if 0xE1 <= b <= 0xEC:
            if i + 2 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0xBF):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            i += 3
            continue
        if b == 0xED:
            if i + 2 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0x9F):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            i += 3
            continue
        if 0xEE <= b <= 0xEF:
            if i + 2 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0xBF):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            i += 3
            continue
        if b == 0xF0:
            if i + 3 >= n:
                return False
            if not (0x90 <= data[i + 1] <= 0xBF):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            if not (0x80 <= data[i + 3] <= 0xBF):
                return False
            i += 4
            continue
        if 0xF1 <= b <= 0xF3:
            if i + 3 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0xBF):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            if not (0x80 <= data[i + 3] <= 0xBF):
                return False
            i += 4
            continue
        if b == 0xF4:
            if i + 3 >= n:
                return False
            if not (0x80 <= data[i + 1] <= 0x8F):
                return False
            if not (0x80 <= data[i + 2] <= 0xBF):
                return False
            if not (0x80 <= data[i + 3] <= 0xBF):
                return False
            i += 4
            continue
        return False
    return True
