"""Check grouped watch ranges against exhaustive interval overlap."""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from synthetic_watchpoints import group_ranges, intersections

rng = random.Random(0x51a7)
points = sorted(set(rng.randrange(0, 200000) for _ in range(500)))
ranges = group_ranges(points, max_gap=128)
assert all(any(lo <= p and p + 31 <= hi for lo, hi in ranges) for p in points)
for address, size in [(0, 1), (points[0] - 31, 1), (points[0] - 31, 32),
                      (points[-1] + 31, 1), (points[-1] + 32, 1)]:
    assert intersections(points, address, size) == [p for p in points if address < p + 32 and p < address + size]
for _ in range(10000):
    address, size = rng.randrange(0, 200000), rng.randrange(1, 129)
    assert intersections(points, address, size) == [p for p in points if address < p + 32 and p < address + size]
print('PASS: grouped watch coverage and exact interval matching')
