# Hawk survey results

This follows the 119 surveys and the groups on the [Scheme Surveys index](https://docs.scheme.org/surveys/). The Hawk result is the current repository behavior where the survey is executable against Hawk; for implementation comparisons, it records the corresponding Hawk capability. “Not applicable” means the survey asks about a feature Hawk does not expose or about another implementation’s metadata.

## Features

|  # | Survey                         | Tiny summary                                              | Hawk result                                                                                                   |
|---:|--------------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
|  1 | C++                            | Which Schemes are written in C++ or target C++?           | Hawk is implemented in C23; no C++ target or C++ FFI is exposed.                                              |
|  2 | Comma commands                 | Whether REPL commands use comma syntax.                   | No comma-command REPL interface.                                                                              |
|  3 | Compiler available             | Whether an implementation includes a compiler.            | Yes: Hawk has a tracing JIT compiler and executable runtime.                                                  |
|  4 | Disassemble                    | Whether generated code can be disassembled interactively. | No user-facing disassemble facility was found.                                                                |
|  5 | Five to six to seven           | Language changes across R5RS, R6RS, and R7RS.             | Partial R7RS-small behavior; the existing R7RS tests are split across both test files and pass.               |
|  6 | Implementation language        | Implementation language and generated representation.     | C23 implementation with a tracing JIT and native machine-code generation.                                     |
|  7 | Implementation support         | Which parts of R7RS-small implementations support.        | Hawk targets the R7RS-small surface used by its current test suite; support is incomplete.                    |
|  8 | jiffies-per-second             | Value and availability of `jiffies-per-second`.           | `(jiffies-per-second)` returns `1000000000`; `(current-jiffy)` is available.                                  |
|  9 | Load path                      | How code discovers the currently loaded filename.         | Hawk's loader has a search path configured with `-I` and `-A`; no source-file pathname procedure is exported. |
| 10 | Online help                    | How to request help from the REPL.                        | `hawk -h` prints command-line help; there is no REPL help procedure.                                          |
| 11 | Optionality                    | Which standard facilities are optional.                   | The survey’s optional facilities remain feature-dependent; Hawk implements the tested core subset.            |
| 12 | Profiling                      | Built-in timing and profiling interfaces.                 | `hawk -p` enables the built-in sampling profiler and reports VM/GC/JIT timing.                                |
| 13 | RnRS support                   | Which language standards are supported.                   | R7RS-oriented, with the repository’s R5RS/R7RS tests passing.                                                 |
| 14 | Scheme{number} implementations | Disambiguation of similarly named Schemes.                | Not applicable: Hawk is not one of those implementations.                                                     |
| 15 | Scheme on Windows              | Platform availability across implementations.             | Not assessed by this Linux build; no Windows result is claimed.                                               |
| 16 | Standalone executables         | Whether Scheme programs compile to standalone binaries.   | `hawk --exe program.scm` generates and links a standalone executable from the Scheme program.                 |

## Macros

|  # | Survey                                      | Tiny summary                                              | Hawk result                                                                                      |
|---:|---------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| 17 | Improper syntax-rules patterns              | Whether improper ellipsis patterns are accepted.          | Hawk rejects the improper `syntax-rules` pattern during expansion.                               |
| 18 | Macroexpand                                 | How a macro can be expanded for inspection.               | No public `macroexpand` procedure is exposed.                                                    |
| 19 | Syntax definitions                          | Which macro definition systems are supported.             | `define-syntax` with `syntax-rules` is supported; no `define-macro` result is claimed.           |
| 20 | Self-referential macro                      | Expansion of a macro that expands to its own keyword.     | Hawk reports a syntax/expansion error rather than producing a recursive value.                   |
| 21 | Redefining special forms                    | Whether special forms can be rebound or replaced.         | Hawk rejects attempts to redefine core special forms during expansion.                           |
| 22 | Syntax definitions - to infinity and beyond | Behavior of infinitely recursive macro expansion.         | Not run: the expression is deliberately nonterminating; Hawk would need a timeout-limited probe. |
| 23 | Syntax Mutation                             | Changing a transformer binding into a value or procedure. | Hawk does not permit the tested transformer/value mutation.                                      |
| 24 | Hygienic macros                             | How hygienic macro systems are implemented.               | `syntax-rules` provides hygienic macro expansion; the implementation details are internal.       |

## Bindings

|  # | Survey                        | Tiny summary                                                      | Hawk result                                                                                                                                       |
|---:|-------------------------------|-------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| 25 | Chez REPL semantics           | Incremental compiler and interaction-environment behavior.        | Not applicable: Hawk does not implement Chez’s REPL semantics.                                                                                    |
| 26 | `define-syntax` defines       | Whether a macro can introduce a top-level definition.             | The tested macro defines `x`; evaluating `x` returns `32`.                                                                                        |
| 27 | Definitions in `cond` clauses | Whether `define` is accepted inside a `cond` clause.              | Hawk rejects the tested clause with an internal invalid-IR error.                                                                                 |
| 28 | Empty `define`                | Meaning of `(define x)`.                                          | Hawk reports an error for the empty definition.                                                                                                   |
| 29 | Eval `define`                 | Whether `eval` accepts a definition.                              | `(eval '(define x 32) (interaction-environment))` returns `32`; the new binding is not visible as a normal script top-level binding.              |
| 30 | Fluid let                     | Availability and scope behavior of `fluid-let`.                   | Evaluating `fluid-let` reports an undefined-form error.                                                                                           |
| 31 | Hygienic inclusion            | Whether included code respects macro hygiene.                     | The macro/include probe reports an error; Hawk does not capture the macro-bound `a` through this include form.                                    |
| 32 | `letrec*`                     | Difference between `letrec`, `letrec*`, and internal definitions. | `letrec*` is available; no direct survey probe was added.                                                                                         |
| 33 | Lisp top levels               | Classification of global-environment models.                      | Hawk’s `interaction-environment` accepts evaluated definitions, while ordinary script bindings remain separate.                                   |
| 34 | Petrofsky let                 | Named-let binding edge case.                                      | The named-let form evaluates the tested case to `-1`.                                                                                             |
| 35 | Redefining keywords           | Rebinding a syntax keyword as a variable.                         | Hawk keeps core syntax bindings protected; the survey redefinition reports an error.                                                              |
| 36 | Redefining syntax             | Replacing a variable with syntax and vice versa.                  | The first variable-to-syntax case works through expansion; the complete replacement matrix was probed only for the supported syntax-rules subset. |
| 37 | Redundant imports             | Conflicting and duplicate library imports.                        | Hawk rejects conflicting library bindings; duplicate same-library imports are accepted by the library loader.                                     |
| 38 | Set syntax                    | Effects of mutating a binding used by a macro.                    | The tested local macro expands to `-3` after the `set!`; expansion uses the captured syntax binding.                                              |
| 39 | Set undefined variable        | Result of `(set! missing ...)`.                                   | Hawk signals an error for an unbound variable.                                                                                                    |
| 40 | Syntax abuse                  | Whether a keyword in value position is syntax or a variable.      | Hawk reports an error for the invalid syntax case.                                                                                                |

## Evaluation

|  # | Survey                 | Tiny summary                                                 | Hawk result                                                                                       |
|---:|------------------------|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| 41 | Apply args limit       | Practical maximum list length passed through `apply`.        | Applying `list` to 10,000 generated arguments succeeds; no upper limit was sought.                |
| 42 | Argument order         | Order of procedure argument evaluation.                      | The probe evaluates arguments left-to-right: side effects produce `(2 1)`.                        |
| 43 | Call/cc                | Availability and behavior of the `call/cc` alias.            | `call/cc` works; the continuation re-entry smoke test passes.                                     |
| 44 | `cond-expand`          | Handling of unknown requirement forms and short-circuiting.  | Unknown requirements short-circuit correctly; the survey test passes.                             |
| 45 | Empty list             | Whether `'()` is self-evaluating.                            | `'()` is true in conditionals, but evaluating the empty datum through `eval` raises an error.     |
| 46 | Eval procedure         | Result of evaluating a procedure object.                     | Evaluating the primitive procedure object with `eval` reports an error.                           |
| 47 | Force non-promise      | Applying `force` to an ordinary value.                       | `(force 5)` reports an error.                                                                     |
| 48 | Guard behavior         | Nested exception handling and dynamic-wind ordering.         | `guard` catches the tested runtime errors; the full nested event sequence was not used.           |
| 49 | Multiple values        | Values in single-value and sequence contexts.                | `(begin (values 1 2) 3)` returns `3`; a multiple-value argument in a single-value context errors. |
| 50 | One-armed `if`         | Value produced when a one-armed `if` test is false.          | `(if #f 1)` returns Hawk’s `#<undefined>` value.                                                  |
| 51 | Parameters and threads | Parameter mutation across spawned threads.                   | No thread survey result; threads are not part of this test surface.                               |
| 52 | Petrofsky catastrophe  | Continuation re-entry in `(+ ...)` position.                 | The canonical expression returns `1` and passes the survey test.                                  |
| 53 | Recursive values       | Nested `values` behavior in `let-values`.                    | Hawk reports an error for the survey’s nested `let-values` case.                                  |
| 54 | Self-quoting vectors   | Whether a vector can appear without quotation.               | A literal vector is read as data and evaluates successfully.                                      |
| 55 | What `load` returns    | Values returned when a loaded file produces multiple values. | Loading a file containing `(values 1 2 3)` returns the first value, `1`, in this context.         |

## Identity and mutability

|  # | Survey                          | Tiny summary                                                  | Hawk result                                                                                                             |
|---:|---------------------------------|---------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| 56 | Boolean=?                       | Equality procedure specialized for booleans.                  | `(boolean=? #t #t #f)` returns `#f`; variadic boolean equality is supported.                                            |
| 57 | Char eq                         | Whether identical character literals are `eq?`.               | Character equality is available; no identity guarantee was recorded.                                                    |
| 58 | Default values for constructors | Default elements of lists, vectors, strings, and bytevectors. | `make-list` yields `()`, `make-vector` yields `0`, `make-string` yields `#\null`, and a one-byte bytevector yields `0`. |
| 59 | Disjoint promises               | Whether promises are disjoint from procedures.                | `(procedure? (delay 1))` returns `#f`; promises are disjoint from procedures.                                           |
| 60 | Empty strings/vectors           | Identity of separately created empty aggregates.              | Separate empty strings and vectors are not `eq?` (`#f`, `#f`).                                                          |
| 61 | Exception taxonomies            | Names and hierarchies of condition types.                     | Hawk has error handling but no documented portable taxonomy matching this survey.                                       |
| 62 | Immediate strings coalesced     | Whether equal string literals share identity.                 | Two separately created empty strings are not `eq?`; Hawk does not promise literal-string interning.                     |
| 63 | Immutable literals              | Whether literal pairs can be mutated.                         | Literal pairs are mutable: changing `'(a b)` produces `(c b)`.                                                          |
| 64 | Immutable strings               | Whether literal strings can be changed.                       | Literal strings are mutable: changing `"abc"` produces `"xbc"`.                                                         |
| 65 | Nil is false                    | Whether the empty list is false.                              | `()` is true in conditionals, as required by R7RS.                                                                      |
| 66 | Read mutable                    | Mutability of pairs returned by `read`.                       | Read pairs are mutable; the survey test passes.                                                                         |
| 67 | Void value                      | Procedures and syntax for an unspecified/void value.          | Hawk uses `#<undefined>` for unspecified results; `void` and `undefined` are not exported procedures.                   |

## Lexical syntax

|  # | Survey                                        | Tiny summary                                                 | Hawk result                                                                                                         |
|---:|-----------------------------------------------|--------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| 68 | Backslash bar                                 | Whether `\|` is accepted in string literals.                 | Accepted; `"\|"` reads and writes as `"\|"`.                                                                        |
| 69 | Brackets/braces                               | Meaning of square brackets and curly braces.                 | Square-bracket list syntax is rejected by the reader.                                                               |
| 70 | Case insensitivity                            | Case rules for symbols, characters, booleans, and numbers.   | Hawk uses case-sensitive Scheme identifiers.                                                                        |
| 71 | Comma in identifiers                          | Whether commas can occur in identifiers.                     | `a,` is rejected as an invalid symbol.                                                                              |
| 72 | Datum labels                                  | Reader support for `#n=` and `#n#`.                          | Datum labels are read; the identity test returns `#f`, so labels are not preserved as shared identity in that case. |
| 73 | Dot comma                                     | Reader treatment of `.,` in a datum.                         | `.,` is rejected by the reader.                                                                                     |
| 74 | Empty symbol concatenated                     | Reader behavior for an empty symbol escape next to text.     | The concatenated empty symbol form produces an empty-symbol lookup error.                                           |
| 75 | Hash bang EOF                                 | Whether `#!eof` terminates input.                            | `#!eof` is rejected as an invalid hash form.                                                                        |
| 76 | Hash in identifiers                           | Whether `#` can occur inside an identifier.                  | `a#b` is rejected by the reader.                                                                                    |
| 77 | Hash-quote                                    | Meaning of the `#"..."` reader syntax.                       | `#"..."` is rejected as an unknown hash form.                                                                       |
| 78 | Keyword syntax                                | Self-evaluating keyword forms such as `:foo` or `#:foo`.     | No keyword syntax is exposed.                                                                                       |
| 79 | One plus x                                    | Whether `1+x` and `1+`-style names are readable identifiers. | Identifiers beginning with a digit, including `1+`, are rejected.                                                   |
| 80 | Quote delimiter                               | Whether `'` terminates a symbol.                             | `'` is a delimiter for normal quote syntax, but `a'b` is rejected as one symbol.                                    |
| 81 | Reader: vertical bar concatenated with number | Interpretation of `\|1\|1` and similar tokens.               | The concatenated vertical-bar/number form fails with an undefined-symbol error.                                     |
| 82 | Square brackets                               | Whether `[a b c]` is accepted as list syntax.                | `[a b c]` is rejected by the reader.                                                                                |
| 83 | `string->symbol` conversion                   | Escaping characters that need symbol delimiters.             | `(string->symbol "a b")` succeeds and preserves the space in the symbol.                                            |
| 84 | Unsigned imaginary                            | Reader behavior for `35i`.                                   | `35i` is rejected by the reader.                                                                                    |
| 85 | Upper-case escape                             | Reader behavior for an uppercase string escape.              | `\N` is accepted as the literal character `N`; it is not a named escape.                                            |
| 86 | Vertical-line symbols                         | Reader support for `\|...\|` symbols.                        | Vertical-bar symbols are supported; `\|a b\|` reads as one symbol.                                                  |

## Pairs and lists

|  # | Survey         | Tiny summary                                           | Hawk result                                                                             |
|---:|----------------|--------------------------------------------------------|-----------------------------------------------------------------------------------------|
| 87 | Improper lists | `memq` behavior on an improper list.                   | `memq` finds the object and returns the improper tail; the survey test passes.          |
| 88 | Property lists | Common Lisp-style property-list support.               | No Common Lisp property-list API is exported; ordinary association lists are available. |
| 89 | Circular lists | Behavior of `length` and `map` on circular structures. | `length` detects circular lists and reports an error rather than looping indefinitely.  |

## I/O and character encoding

|  # | Survey                      | Tiny summary                                                 | Hawk result                                                                                                  |
|---:|-----------------------------|--------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| 90 | CWIF close port             | Port state after `call-with-input-file` closes it.           | The tested `call-with-input-file` case raises an error before the post-exception read; no value is returned. |
| 91 | Embedded CR+LF              | Reader behavior for CR+LF source line endings.               | An embedded CR+LF contributes two characters; `(string-length "abc\r\ndef")` returns `8`.                    |
| 92 | Get from closed string port | Whether output can be retrieved after closing a string port. | `get-output-string` on a closed port returns the empty string.                                               |
| 93 | JSON representations        | How Scheme values map to JSON.                               | No JSON library or standard mapping is exposed.                                                              |
| 94 | `read-line`                 | Line termination and EOF behavior.                           | Line endings are stripped and EOF is reported correctly; the survey test passes.                             |
| 95 | Readtables                  | Support for programmable Common Lisp-style readers.          | No programmable readtable API is exported.                                                                   |
| 96 | `string-titlecase`          | Unicode multi-character titlecase behavior.                  | `string-titlecase` is undefined.                                                                             |
| 97 | Unicode lambda              | Whether `λ` is accepted as an alternative to `lambda`.       | The UTF-8 `λ` reader form is accepted as an identifier.                                                        |
| 98 | Unicode support             | Character, string, and identifier Unicode ranges.            | Unicode characters, strings, and identifiers are supported through the Unicode scalar range; UTF-8 conversion is supported. |

## Numbers

|   # | Survey                               | Tiny summary                                                | Hawk result                                                                                                                        |
|----:|--------------------------------------|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
|  99 | Is `abs` the same as complex norm?   | Result of `(abs -3-4i)`.                                    | `(abs -3-4i)` reports an error.                                                                                                    |
| 100 | Complex conjugate                    | Whether `conjugate` is a core procedure.                    | `conjugate` is undefined.                                                                                                          |
| 101 | Complex logarithm                    | Complex result of `(atanh -2)`.                             | Hawk returns `+nan.0` for the tested expression.                                                                                   |
| 102 | Complex representations              | Exact, inexact, and mixed complex-number representations.   | Complex numbers are supported; mixed representation behavior was not fully characterized.                                          |
| 103 | Exact `expt`                         | Whether exact exponentiation remains exact.                 | `(expt 1/3 3)` returns exact `1/27`.                                                                                               |
| 104 | Exact `sqrt`                         | Whether `(sqrt 25/4)` remains exact.                        | It remains exact.                                                                                                                  |
| 105 | Overflow in `expt`                   | Behavior of an impossibly large exponent.                   | Not run: the survey warns that it can loop, abort, crash, or exhaust memory.                                                       |
| 106 | Fixnum info                          | Implementation-specific fixnum ranges.                      | Hawk fixnums are signed 60-bit values: `2^60 - 1` is a fixnum and `2^60` is not.                                                   |
| 107 | Float precision                      | Accepted float precisions and representations.              | Hawk supports one inexact representation: IEEE-style double flonums; alternate `s`/`f`/`l` precisions are not exposed.             |
| 108 | Log and sqrt require floating point? | Operations on very large bignums.                           | Not run: the survey uses a 2,480-digit value and behavior is implementation-specific.                                              |
| 109 | Hyperbolic trigonometric functions   | Availability and edge behavior of hyperbolic functions.     | `sinh`, `cosh`, `tanh`, `asinh`, `acosh`, and `atanh` are undefined.                                                               |
| 110 | Max Inf/NaN                          | `max` behavior with infinities and NaNs.                    | `max +inf.0 0` returns `+inf.0`; `max +nan.0 0` returns an inexact value.                                                          |
| 111 | Negative rationalize                 | Meaning of a negative tolerance to `rationalize`.           | `(rationalize 20 -1)` returns `19`.                                                                                                |
| 112 | Negative sqrt                        | Result of `(sqrt -1)`.                                      | Hawk returns a complex result for negative square root; exactness was not made a portability assertion.                            |
| 113 | Non-finite numbers                   | Syntax, predicates, and arithmetic for infinities and NaNs. | `infinite?`, `finite?`, `nan?`, NaN inequality, and opposite-infinity NaN behavior pass the survey tests.                          |
| 114 | Numeric tower                        | Which numeric tower parts are implemented.                  | Direct probes confirm exact rationals, double flonums, and complex numbers; `fixnum?` is internal and `exact-integer?` aliases it. |
| 115 | Prefixed `string->number`            | Whether `#x` prefixes work in strings.                      | `(string->number "#x10")` returns `16`.                                                                                            |
| 116 | Random number generation             | Seeds, algorithms, and reproducibility.                     | No standard random-number procedure is exported in the tested libraries.                                                           |
| 117 | Round Inf                            | Behavior of `round` on positive infinity.                   | `(round +inf.0)` returns `+inf.0`.                                                                                                 |
| 118 | Short equality                       | Behavior of `=` with fewer than two arguments.              | Hawk accepts the extension `(= 1)`; this is recorded but not asserted as portable.                                                 |
| 119 | Zero                                 | Signed zero, zero predicates, and zero arithmetic.          | `zero? -0.0` is true; `0 * +inf.0` produces an accepted zero-or-NaN result.                                                        |
