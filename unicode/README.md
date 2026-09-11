# Unicode tables

Run `python3 unicode/generate.py` manually from the repository root. It downloads
Unicode 17.0.0 inputs into `unicode/cache/17.0.0/`, validates the compressed tables
exhaustively, and replaces `tables.scm`. Use `--offline` to require cached inputs,
or `--cache DIR` to choose another cache. Check in the generator and generated
output together. No build step runs this script or accesses the network.

Tables use sorted inclusive property ranges, simple mapping records
(start, end, stride, delta), decimal digit zeros, and full-case exceptions.
`runtime.scm` supplies binary searches and string operations; ASCII bypasses tables.
Casing is locale-independent. String lowercasing always maps sigma to U+03C3,
as permitted by R7RS. Unicode data terms: https://www.unicode.org/license.txt
Source SHA-256 checksums and the pinned release are recorded in the output.
