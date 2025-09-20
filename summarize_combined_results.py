import argparse
import os
from datetime import datetime


def read_domains_simple(path):
    """Read a plain domain list (one domain per line). Returns a set."""
    s = set()
    if not os.path.exists(path):
        return s
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            s.add(line.lower())
    return s


def read_domains_special_status(path):
    """Read special status list: lines are `domain status reason`.

    Returns:
      - domains_set: set of domain strings (deduped)
      - first_line_by_domain: dict domain -> original detailed line (first occurrence)
    """
    domains_set = set()
    first_line_by_domain = {}
    if not os.path.exists(path):
        return domains_set, first_line_by_domain
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if not parts:
                continue
            domain = parts[0].lower()
            if domain not in first_line_by_domain:
                first_line_by_domain[domain] = line
            domains_set.add(domain)
    return domains_set, first_line_by_domain


def detect_suffix(any_domain):
    if not any_domain:
        return ''
    parts = any_domain.split('.')
    if len(parts) >= 2:
        return '.' + parts[-1]
    return ''


def detect_length(any_domain):
    if not any_domain:
        return None
    main = any_domain.split('.')[0]
    return len(main)


def detect_pattern(any_domain):
    if not any_domain:
        return 'D'
    main = any_domain.split('.')[0].lower()
    if main.isalpha():
        return 'D'
    if main.isdigit():
        return 'd'
    return 'a'


def expected_space_size(length, pattern):
    if length is None:
        return None
    if pattern == 'D':
        return 26 ** length
    if pattern == 'd':
        return 10 ** length
    if pattern == 'a':
        return 36 ** length
    return None


def main():
    parser = argparse.ArgumentParser(description='Summarize combined domain scan results with dedup and mutual exclusion.')
    parser.add_argument('--dir', default='domain-scan-results-combined', help='Directory containing combined result files')
    parser.add_argument('--available', default='available_domains_all.txt', help='Available domains file name')
    parser.add_argument('--registered', default='registered_domains_all.txt', help='Registered domains file name')
    parser.add_argument('--special', default='special_status_domains_all.txt', help='Special-status domains file name')
    parser.add_argument('--summary', default='summary.txt', help='Summary output file name')
    parser.add_argument('--rewrite', action='store_true', help='Rewrite combined files with deduped, exclusive contents')
    args = parser.parse_args()

    base = args.dir
    avail_path = os.path.join(base, args.available)
    reg_path = os.path.join(base, args.registered)
    spec_path = os.path.join(base, args.special)
    summary_path = os.path.join(base, args.summary)

    available = read_domains_simple(avail_path)
    registered_raw = read_domains_simple(reg_path)
    special, special_line = read_domains_special_status(spec_path)

    # Enforce mutual exclusion:
    # - available and registered are already disjoint in current data, keep it as is
    # - remove any special domains from registered to avoid double counting
    registered_only = registered_raw - special
    available_only = available - special - registered_raw  # defensive; should be no overlap
    special_only = special

    # Overlaps (for diagnostics)
    overlap_reg_spec = registered_raw & special
    overlap_avail_spec = available & special
    overlap_avail_reg = available & registered_raw

    # Determine metadata
    sample_domain = next(iter(available or registered_raw or special), '')
    suffix = detect_suffix(sample_domain)
    length = detect_length(sample_domain)
    pattern = detect_pattern(sample_domain)
    expected_total = expected_space_size(length, pattern)

    union_total = len(available_only | registered_only | special_only)

    # Optionally rewrite combined files with cleaned contents
    if args.rewrite:
        # Available: write available_only (sorted)
        with open(avail_path, 'w', encoding='utf-8') as f:
            for d in sorted(available_only):
                f.write(d + '\n')

        # Registered: write registered_only (sorted)
        with open(reg_path, 'w', encoding='utf-8') as f:
            for d in sorted(registered_only):
                f.write(d + '\n')

        # Special: write header + first occurrence detailed lines for each domain (sorted by domain)
        with open(spec_path, 'w', encoding='utf-8') as f:
            f.write('# Special Status Domains\n')
            f.write('# Format: domain status reason\n')
            f.write('#\n')
            for d in sorted(special_only):
                line = special_line.get(d, d)
                f.write(line + '\n')

    # Write summary
    lines = []
    lines.append('Batch Scan Results Summary')
    lines.append('=================================')
    lines.append(f'Base Domain: {suffix if suffix else "(unknown)"}')
    lines.append(f'Domain Length: {length if length is not None else "(unknown)"}')
    lines.append(f'Pattern: {pattern}')
    lines.append('Batches: 0 to 25')
    lines.append(f'Available domains: {len(available_only)}')
    lines.append(f'Registered domains: {len(registered_only)}')
    lines.append(f'Special status domains: {len(special_only)}')
    lines.append('')
    lines.append(f'Total unique domains (union): {union_total}')
    if expected_total is not None:
        lines.append(f'Expected space size (pattern {pattern}): {expected_total}')
        delta = union_total - expected_total
        lines.append(f'Delta (union - expected): {delta}')
    lines.append('')
    lines.append('Overlap diagnostics (before exclusion):')
    lines.append(f'- registered ∩ special: {len(overlap_reg_spec)}')
    lines.append(f'- available  ∩ special: {len(overlap_avail_spec)}')
    lines.append(f'- available  ∩ registered: {len(overlap_avail_reg)}')
    lines.append('')
    lines.append(f'Generated at: {datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y")}')

    os.makedirs(base, exist_ok=True)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    # Also print to stdout for convenience
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
