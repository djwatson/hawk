# TODO list

* side-exit hot traces

* reg alloc
* fixup all opcodes of 'D' type
* various check for const size overflow, reg or opcode overflow
* fuzz bytecode reader
* remove indirection for consts/bc
* Add define tags/header for runtime types

# Bytecode generator

## CLEANUP
* cleanup bytecode ops order
* split bc to separate files
* Double check 'VN' use D reg

## TODO
* comments in output
* name more lambdas, define, let
*could add sume 'VN' variations of < >, EQ, etc


* lets shouldn't be modified by alexpander, but get let loop working (let-internal?)
* rest params
* assignment conversion
* closure conversion
* fix letrec
* tail call register alloc?

