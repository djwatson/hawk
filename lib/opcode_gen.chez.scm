(define open-output-file-chez open-output-file)
(define (open-output-file f) (open-output-file-chez f 'replace ))
(include "opcode_gen.scm")
