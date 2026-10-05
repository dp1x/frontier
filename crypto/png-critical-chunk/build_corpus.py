"""Build the unknown-critical-chunk vector corpus, emit vectors.jsonl, and
print the corpus table.

Run:
    python build_corpus.py           # build, write vectors.jsonl, print table
    python build_corpus.py --debug   # same, plus per-vector spec reasoning

The corpus is intentionally SMALL. Every row must discriminate between
hypotheses; padding it is a defect (see Agents.md anti-slop constraints).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import png_gen as G
import png_oracle as O

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(OUT_DIR, 'vectors.jsonl')
BYTES_DIR = os.path.join(OUT_DIR, 'vectors')

UNKNOWN = G.UNKNOWN_CHUNK_DATA


def _vector(name, group, tier, purpose, payload: bytes):
    """Assemble, analyse, and record one vector."""
    verdict = O.analyse(payload)
    probe = _find_probe_chunk(verdict, name)
    return {
        'name': name,
        'group': group,
        'tier': tier,
        'purpose': purpose,
        'bytes_len': len(payload),
        'sha256': hashlib.sha256(payload).hexdigest(),
        'probe_chunk': probe,
        'expected_reason': verdict.reason,
        'expected_decision': O.expected_decision(verdict),
        'expected_detail': verdict.detail,
        'spec_basis': verdict.spec_basis,
        'is_confound': verdict.is_confound,
        'all_chunk_crcs_valid': all(c.crc_ok for c in verdict.chunks),
        'chunk_types': [
            {'type': c.props.text, 'hex': c.props.hex, 'offset': c.offset,
             'length': c.length, 'crc': c.crc_hex,
             'crc_ok': c.crc_ok,
             'ancillary_bit': c.props.ancillary_bit,
             'known_to_spec': c.props.known_to_spec}
            for c in verdict.chunks
        ],
        '_payload': payload,
    }


def _find_probe_chunk(verdict, name):
    """Identify the injected chunk of interest (the one that is not part of
    the IHDR/IDAT/IEND baseline)."""
    for c in verdict.chunks:
        if c.type_bytes not in (b'IHDR', b'IDAT', b'IEND'):
            return {'type': c.props.text, 'hex': c.props.hex,
                    'offset': c.offset, 'length': c.length,
                    'crc': c.crc_hex, 'crc_ok': c.crc_ok,
                    'ancillary_bit': c.props.ancillary_bit,
                    'private_bit': c.props.private_bit,
                    'reserved_bit': c.props.reserved_bit,
                    'safe_to_copy_bit': c.props.safe_to_copy_bit,
                    'known_to_spec': c.props.known_to_spec}
    return None


def build():
    A = G.unknown_ancillary_type()
    C = G.unknown_critical_type()

    anc = G.make_chunk(A, UNKNOWN)
    cri = G.make_chunk(C, UNKNOWN)
    anc_badcrc = G.make_chunk(A, UNKNOWN, corrupt_crc=True)
    cri_badcrc = G.make_chunk(C, UNKNOWN, corrupt_crc=True)
    gam = G.make_chunk(b'gAMA', G.gamа_data())
    txt = G.make_chunk(b'tEXt', G.text_data())

    v = []

    # ---- (a) harness self-check / positive controls ------------------------
    v.append(_vector(
        'ctl-00-minimal', 'positive_control', 'primary',
        'Smallest conforming PNG, no injected chunk. Proves the harness can '
        'produce ACCEPT.',
        G.minimal_png()))
    v.append(_vector(
        'ctl-01-known-ancillary-gAMA', 'positive_control', 'primary',
        'Baseline plus a KNOWN ancillary chunk (gAMA). Proves that adding a '
        'legitimate ancillary chunk does not trip the unknown-chunk rule.',
        G.minimal_png(extra_after_ihdr=gam)))
    v.append(_vector(
        'ctl-02-known-ancillary-tEXt', 'positive_control', 'primary',
        'Baseline plus a KNOWN ancillary chunk (tEXt). Second known-ancillary '
        'control.',
        G.minimal_png(extra_after_ihdr=txt)))
    v.append(_vector(
        'ctl-03-known-critical-PLTE', 'positive_control', 'primary',
        'Baseline (truecolor, colour type 2) plus a KNOWN critical chunk (PLTE) '
        'that a conforming decoder must understand. Colour type 2 makes PLTE '
        'legal per spec 11.2.2 ("may appear for color types 2 and 6"). '
        'Proves a recognized CRITICAL chunk is not mistaken for an unknown one.',
        G.minimal_png_color(
            extra_after_ihdr=G.make_chunk(b'PLTE', b'\x00\x00\x00'),
            color_type=2)))

    # ---- (b) THE decisive paired vectors (primary) ------------------------
    v.append(_vector(
        'pair-primary-anc', 'decisive_pair', 'primary',
        'DECISIVE. Unknown ANCILLARY chunk vQAx between IHDR and IDAT. Spec '
        '5.4/Table 6: ancillary bit=1 -> decoder may safely ignore. Expected '
        'ACCEPT.',
        G.minimal_png(extra_after_ihdr=anc)))
    v.append(_vector(
        'pair-primary-cri', 'decisive_pair', 'primary',
        'DECISIVE. Unknown CRITICAL chunk VQAx between IHDR and IDAT. Byte-'
        'identical to pair-primary-anc except bit 5 (0x20) of the type field '
        'and the resulting CRC. Spec 5.4/Table 6 + 15.3.3(6): error. Expected '
        'REJECT/UNKNOWN_CRITICAL_CHUNK.',
        G.minimal_png(extra_after_ihdr=cri)))

    # ---- (c) placement variants (secondary) -------------------------------
    v.append(_vector(
        'place-anc-after-idat', 'placement', 'secondary',
        'Unknown ANCILLARY vQAx between IDAT and IEND. Tests whether the rule '
        'is applied consistently by position.',
        G.minimal_png(extra_after_idat=anc)))
    v.append(_vector(
        'place-cri-after-idat', 'placement', 'secondary',
        'Unknown CRITICAL VQAx between IDAT and IEND. Placement counterpart.',
        G.minimal_png(extra_after_idat=cri)))

    # ---- (d) negative controls (confound probes) --------------------------
    v.append(_vector(
        'negc-anc-badcrc', 'negative_control', 'primary',
        'NEGATIVE CONTROL. Unknown ANCILLARY vQAx with a deliberately corrupt '
        'CRC. The oracle MUST report CRC_MISMATCH, never ACCEPT and never '
        'UNKNOWN_CRITICAL_CHUNK. Proves the harness can tell the two rejection '
        'reasons apart. MUST NOT be cited as evidence about criticality.',
        G.minimal_png(extra_after_ihdr=anc_badcrc)))
    v.append(_vector(
        'negc-cri-badcrc', 'negative_control', 'primary',
        'NEGATIVE CONTROL. Unknown CRITICAL VQAx with a deliberately corrupt '
        'CRC. Expected CRC_MISMATCH -- this is the exact trap: a decoder that '
        'rejects here is proving only that it checks CRCs, NOT that it honours '
        'the critical-chunk rule. MUST NOT be cited as evidence.',
        G.minimal_png(extra_after_ihdr=cri_badcrc)))

    # ---- (e) extra negative control: reserved bit set ---------------------
    v.append(_vector(
        'negc-anc-reserved-bit', 'negative_control', 'secondary',
        'NEGATIVE CONTROL. Ancillary chunk whose THIRD letter is lowercase, so '
        'the reserved bit is 1. Spec Table 6: the datastream then does not '
        'conform to this version of PNG; 15.3.3(7) treats it as unknown. '
        'Demonstrates a second, independent way a vector can be confounded.',
        G.minimal_png(extra_after_ihdr=G.make_chunk(b'vQax', UNKNOWN))))

    return v


def discriminating_power(vectors):
    """Count vectors whose verdict is evidenceful (ACCEPT or
    UNKNOWN_CRITICAL_CHUNK) and whose CRCs all verify. These are the only
    vectors that can bear on the critical/ancillary rule."""
    return sum(1 for v in vectors
               if v['expected_reason'] in O.EVIDENCEFUL_REASONS
               and v['all_chunk_crcs_valid'])


def pairs(vectors):
    """Identify the decisive ANC/CRI pairs that differ only in criticality.

    Matches any vector whose name contains 'anc' against the sibling with 'cri'
    substituted at the same position, so placement variants pair up too.
    """
    out = []
    for a in vectors:
        if '-anc' not in a['name'] or 'badcrc' in a['name']:
            continue
        cname = a['name'].replace('-anc', '-cri')
        for c in vectors:
            if c['name'] == cname:
                out.append((a, c))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--debug', action='store_true',
                    help='print per-vector spec reasoning')
    args = ap.parse_args()

    vectors = build()

    os.makedirs(BYTES_DIR, exist_ok=True)
    with open(VECTORS_PATH, 'w', encoding='utf-8', newline='\n') as fh:
        for v in vectors:
            with open(os.path.join(BYTES_DIR, v['name'] + '.png'), 'wb') as bf:
                bf.write(v['_payload'])
            rec = {k: val for k, val in v.items() if k != '_payload'}
            fh.write(json.dumps(rec, sort_keys=True) + '\n')

    # ---- table ------------------------------------------------------------
    hdr = ('%-26s %-22s %-5s %-4s %-9s %-8s %-22s %s'
           % ('NAME', 'PROBE TYPE', 'HEX', 'LEN', 'CRC', 'CRC?', 'REASON',
              'DECISION'))
    print(hdr)
    print('-' * len(hdr))
    for v in vectors:
        p = v['probe_chunk']
        if p:
            print('%-26s %-22s %-5s %-4d %-9s %-8s %-22s %s'
                  % (v['name'], p['type'], p['hex'], p['length'], p['crc'],
                     'VALID' if p['crc_ok'] else 'BAD', v['expected_reason'],
                     v['expected_decision']))
        else:
            print('%-26s %-22s %-5s %-4s %-9s %-8s %-22s %s'
                  % (v['name'], '(none)', '-', '-', '-', '-',
                     v['expected_reason'], v['expected_decision']))
    print()

    # byte lengths
    print('BYTE LENGTHS')
    for v in vectors:
        print('   %-26s %5d bytes   sha256=%s'
              % (v['name'], v['bytes_len'], v['sha256'][:16]))
    print()

    # CRC validity
    print('CRC VALIDITY (all chunks in every vector)')
    allok = True
    for v in vectors:
        ok = v['all_chunk_crcs_valid']
        allok = allok and ok
        print('   %-26s %s' % (v['name'], 'ALL VALID' if ok else 'INVALID PRESENT'))
    print('   -> every vector has all-valid CRCs except the negative controls:',
          [v['name'] for v in vectors if not v['all_chunk_crcs_valid']])
    print()

    # decisive pairs
    print('DECISIVE PAIRS (byte-identical except bit 5 of type byte 0)')
    for a, c in pairs(vectors):
        ba, bc = a['_payload'], c['_payload']
        diff = [i for i in range(min(len(ba), len(bc))) if ba[i] != bc[i]]
        same_len = len(ba) == len(bc)
        print('   %-24s vs %-24s  same_len=%s  n_diff_bytes=%d (1 type + 4 CRC)'
              % (a['name'], c['name'], same_len, len(diff)))
    print()

    dp = discriminating_power(vectors)
    print('CORPUS SIZE             : %d vectors' % len(vectors))
    print('DISCRIMINATING POWER    : %d vectors' % dp)
    print('  (evidenceful verdict = ACCEPT or UNKNOWN_CRITICAL_CHUNK,')
    print('   AND all chunk CRCs valid; confounds excluded)')
    print('CONFOUND VECTORS        : %d'
          % sum(1 for v in vectors if v['is_confound']))

    if args.debug:
        print()
        print('=' * 72)
        print('DEBUG: PER-VECTOR SPEC REASONING')
        print('=' * 72)
        for v in vectors:
            print()
            print('### %s  [%s / %s]' % (v['name'], v['group'], v['tier']))
            print('purpose : %s' % v['purpose'])
            verdict = O.analyse(v['_payload'])
            print(O.explain(verdict))


if __name__ == '__main__':
    main()