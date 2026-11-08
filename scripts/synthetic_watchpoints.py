"""Group synthetic read-watch ranges and find exact overlapping objects."""
import bisect


def group_ranges(points, width=32, max_gap=0x10000):
    ordered = sorted(set(points))
    groups = []
    for point in ordered:
        if not groups or point > groups[-1][1] + max_gap:
            groups.append([point, point + width - 1])
        else:
            groups[-1][1] = max(groups[-1][1], point + width - 1)
    return [(lo, hi) for lo, hi in groups]


def intersections(points, address, size, width=32):
    """Return sorted watched starts overlapping guest access [address,address+size)."""
    if size <= 0:
        return []
    first = bisect.bisect_right(points, address - width)
    last = bisect.bisect_left(points, address + size)
    return points[first:last]
