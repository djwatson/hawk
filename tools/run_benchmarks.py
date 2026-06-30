#!/usr/bin/env python3
"""Rebuild and run benchmarks for chez + hawk, then all ablations."""
import argparse, glob, os, shutil, subprocess, sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH_DIR = os.path.join(PROJECT, 'doc', 'bench')
ABLATION_DIR = os.path.join(PROJECT, 'doc', 'paper', 'ablation')
BUILD_DIR = os.path.join(PROJECT, 'build')


def run(cmd, cwd=None, **kwargs):
    print(f"  {cmd}")
    kwargs.setdefault('check', True)
    return subprocess.run(cmd, shell=True, cwd=cwd, **kwargs)


def main():
    parser = argparse.ArgumentParser(description='Rebuild and run benchmarks')
    parser.add_argument('--r7rs-path', required=True)
    parser.add_argument('--hawk-path')
    parser.add_argument('--test', action='store_true',
                        help='Run only ack benchmark (fast)')
    args = parser.parse_args()

    r7rs = os.path.abspath(args.r7rs_path)
    hawk = os.path.abspath(args.hawk_path or os.path.join(BUILD_DIR, 'hawk'))
    bench_arg = 'ack' if args.test else 'all'

    env = os.environ.copy()
    env['HAWK'] = hawk

    # 1 – cmake setup in Release mode
    print("=== cmake Release ===")
    os.makedirs(BUILD_DIR, exist_ok=True)
    run(f'cmake -S {PROJECT} -B {BUILD_DIR} -DCMAKE_BUILD_TYPE=Release', cwd=BUILD_DIR)
    run(f'cmake --build {BUILD_DIR}', cwd=BUILD_DIR)

    # 2 – clean old bench results from both locations
    print("=== clean old results ===")
    for pat in ('results.Hawk*', 'results.Chez*'):
        for f in glob.glob(os.path.join(BENCH_DIR, pat)):
            os.remove(f)
    for f in glob.glob(os.path.join(r7rs, 'results.*')):
        os.remove(f)

    # 3 – chez
    print(f"=== chez {bench_arg} ===")
    for f in glob.glob(os.path.join(r7rs, 'results.*')):
        os.remove(f)
    run(f'./bench chez {bench_arg}', cwd=r7rs, check=False)
    shutil.copy(os.path.join(r7rs, 'results.Chez'), os.path.join(BENCH_DIR, 'results.Chez'))

    # 4 – hawk
    print(f"=== hawk {bench_arg} ===")
    for f in glob.glob(os.path.join(r7rs, 'results.*')):
        os.remove(f)
    run(f'./bench hawk {bench_arg}', cwd=r7rs, env=env, check=False)
    shutil.copy(os.path.join(r7rs, 'results.Hawk'), os.path.join(BENCH_DIR, 'results.Hawk'))

    # 5 – ablations
    patches = sorted(glob.glob(os.path.join(ABLATION_DIR, '*.patch')))
    for pp in patches:
        name = os.path.splitext(os.path.basename(pp))[0]
        suffix = name.replace('-', '_')
        print(f"=== ablation: {name} ===")
        run(f'git apply {pp}', cwd=PROJECT)
        try:
            run(f'cmake --build {BUILD_DIR}', cwd=BUILD_DIR)
            for f in glob.glob(os.path.join(r7rs, 'results.*')):
                os.remove(f)
            run(f'./bench hawk {bench_arg}', cwd=r7rs, env=env, check=False)
            shutil.copy(os.path.join(r7rs, 'results.Hawk'),
                        os.path.join(BENCH_DIR, f'results.Hawk.{suffix}'))
        finally:
            run(f'git apply -R {pp}', cwd=PROJECT)

    print("=== done ===")


if __name__ == '__main__':
    main()
