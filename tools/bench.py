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

    print(f'{"Test":<20} {"Old":>8} {"New":>8} {"Abs Change":>10} {"% Change":>10}')
    print('-' * 56)

    changes = []
    for t in sorted(set(list(old.keys()) + list(new.keys()))):
        o = old.get(t)
        n = new.get(t)
        if o is not None and o > 0 and n is not None:
            pct = ((n - o) / o) * 100
            abs_diff = n - o
            changes.append((t, pct, abs_diff))
            marker = '' if pct < 25 else ' ***'
            print(f'{t:<20} {o:>8.2f} {n:>8.2f} {abs_diff:>+10.2f} {pct:>+9.1f}%{marker}')
        elif o is not None and n is not None:
            print(f'{t:<20} {str(o):>8} {str(n):>8}')
        else:
            print(f'{t:<20} {str(o):>8} {str(n):>8}')

    print()
    good = [(t, p, a) for t, p, a in changes if p < -5]
    slight_good = [x for x in changes if -5 <= x[1] <= 0]
    slight_bad = [x for x in changes if 0 < x[1] <= 5]
    bad = [(t, p, a) for t, p, a in changes if p > 5]

    print(f'Faster (>5% improvement): {len(good)} tests, avg {sum(p for _,p,_ in good)/len(good):.1f}% ({sum(a for _,_,a in good):+.2f})' if good else 'No significantly faster tests')
    print(f'Slightly faster (0-5%):  {len(slight_good)} tests')
    print(f'Slightly slower (0-5%): {len(slight_bad)} tests')
    print(f'Slower (>5% degradation): {len(bad)} tests, avg {sum(p for _,p,_ in bad)/len(bad):.1f}% ({sum(a for _,_,a in bad):+.2f})' if bad else 'No significantly slower tests')
    print(f'Total comparable: {len(changes)} tests')

    changes.sort(key=lambda x: x[2])
    print()
    print('Better:')
    for t, p, a in changes:
        if a < -.2:
            print(f'  {t}: {p:+.1f}% ({a:+.2f})')
    print('Worse:')
    for t, p, a in reversed(changes):
        if a > .2:
            print(f'  {t}: {p:+.1f}% ({a:+.2f})')

    total_old = sum(old[t] for t, _, _ in changes)
    total_new = sum(new[t] for t, _, _ in changes)
    if total_old > 0:
        abs_diff = total_new - total_old
        pct_diff = (abs_diff / total_old) * 100
        print()
        print(f'Total time: {total_old:.2f} -> {total_new:.2f}, diff {abs_diff:+0.2f} ({pct_diff:+0.1f}%)')

if __name__ == '__main__':
    main()
