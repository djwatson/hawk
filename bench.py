#!/usr/bin/env python3
import sys
import argparse
def parse_bench(filename):
    results = {}
    current_name = None
    with open(filename) as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if stripped.startswith('bench2/'):
                current_name = stripped.replace('bench2/', '').strip()
            elif current_name is not None:
                try:
                    results[current_name] = float(stripped)
                except ValueError:
                    pass
                current_name = None
    return results

def main():
    parser = argparse.ArgumentParser(description='Compare two benchmark files')
    parser.add_argument('old', help='First benchmark file to compare')
    parser.add_argument('new', help='Second benchmark file to compare')
    args = parser.parse_args()

    old_file = args.old
    new_file = args.new

    old = parse_bench(old_file)
    new = parse_bench(new_file)

    print(f'{"Test":<20} {"Old":>8} {"New":>8} {"% Change":>10}')
    print('-' * 50)

    changes = []
    for t in sorted(set(list(old.keys()) + list(new.keys()))):
        o = old.get(t)
        n = new.get(t)
        if o is not None and o > 0 and n is not None:
            pct = ((n - o) / o) * 100
            changes.append((t, pct))
            marker = '' if pct < 25 else ' ***'
            print(f'{t:<20} {o:>8.2f} {n:>8.2f} {pct:>+9.1f}%{marker}')
        elif o is not None and n is not None:
            print(f'{t:<20} {str(o):>8} {str(n):>8}')
        else:
            print(f'{t:<20} {str(o):>8} {str(n):>8}')

    print()
    good = [p for _, p in changes if p < -5]
    slight_good = [p for _, p in changes if -5 <= p <= 0]
    slight_bad = [p for _, p in changes if 0 < p <= 5]
    bad = [p for _, p in changes if p > 5]

    print(f'Faster (>5% improvement): {len(good)} tests, avg {sum(good)/len(good):.1f}%' if good else 'No significantly faster tests')
    print(f'Slightly faster (0-5%):  {len(slight_good)} tests')
    print(f'Slightly slower (0-5%): {len(slight_bad)} tests')
    print(f'Slower (>5% degradation): {len(bad)} tests, avg {sum(bad)/len(bad):.1f}%' if bad else 'No significantly slower tests')
    print(f'Total comparable: {len(changes)} tests')

    changes.sort(key=lambda x: x[1])
    print()
    print('Better than 2x:')
    for t, p in changes:
        if p < -50:
            print(f'  {t}: {p:+.1f}%')
    print('Worse by 2x:')
    for t, p in reversed(changes):
        if p > 50:
            print(f'  {t}: {p:+.1f}%')

if __name__ == '__main__':
    main()
