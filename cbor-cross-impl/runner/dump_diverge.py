"""Quick utility to dump diverging rows from matrix.tsv."""
import csv
import sys

with open(sys.argv[1]) as f:
    reader = csv.DictReader(f, delimiter="\t")
    for row in reader:
        if row["verdict"] not in ("PASS",):
            # Shorten expected/actual hex to first 40 chars
            exp = (row["expected_hex"] or "")[:40]
            act = (row["actual_hex"] or "")[:40]
            print(f"  {row['axis']:<30} {row['vector_id']:<30} {row['mode']:<10} {row['verdict']:<18}")
            print(f"      expected: {exp}{'...' if len(row.get('expected_hex') or '') > 40 else ''}")
            print(f"      actual:   {act}{'...' if len(row.get('actual_hex') or '') > 40 else ''}")
            print()