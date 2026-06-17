# Hawk Paper Build

Build the paper PDF from Markdown:

```sh
python3 doc/paper/build_paper.py
```

The default is review mode. To select explicitly:

```sh
python3 doc/paper/build_paper.py --review
python3 doc/paper/build_paper.py --camera-ready
```

Outputs:

- `doc/paper/generated/benchmark_percent_x64.pdf`
- `doc/paper/generated/benchmark_percent_aarch64.pdf`
- `doc/paper/generated/time_breakdown_x64.pdf`
- `doc/paper/generated/time_breakdown_aarch64.pdf`
- `doc/paper/generated/trace_counts_x64.pdf`
- `doc/paper/generated/trace_counts_aarch64.pdf`
- `doc/paper/build/hawk-paper.pdf`

The benchmark charts are generated from `doc/bench/*/results.*`. Repeated
`CSVLINE` records keep the last numeric result for each benchmark and
implementation. Each chart uses Chez as the baseline and includes a `TOTAL` bar
computed from the geometric mean of Hawk/Chez runtime ratios.

The PDF is built with ACM's `acmart` class using the two-column `sigplan`
subformat. Review mode adds the `anonymous,review` options; camera-ready mode
omits them. References use BibTeX with `ACM-Reference-Format`.

The required ACM LaTeX files are vendored in `doc/paper/tex` so the build does
not depend on a system-wide `acmart` install. `acmart.cls` was generated from
the included `acmart.dtx`/`acmart.ins` source files from CTAN.
