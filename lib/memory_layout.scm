; Tags for dynamic  objects.
;; fixnum is zero, so add/sub can be done without untagging.
;; ptr-untag can be instruction combined with lookup on most
;; architectures (i.e. car would be consp[8 - 1 /* untag */])
(define max-reg-args 6)

(define fixnum-tag #b000)
(define ptr-tag #b001)
(define flonum-tag #b010)
(define cons-tag #b011)
(define literal-tag #b100)
(define closure-tag #b101)
(define symbol-tag #b110)
(define vector-tag #b111)
;; ptr-tagged objects. First eight bytes store these tags, bottom bits '001'.
(define ptr-unused1-tag #x01)
(define string-tag #x09)
(define func-tag #x11)
(define ptr-unused2-tag #x19)
(define box-tag #x21)
(define cont-tag #x29)
(define record-tag #x31)

;; literals, using literal-tag (bottom three bits = #b100)
(define bool-tag #x04)
(define true-rep #x00000104)
(define false-rep #x00000004)
(define char-tag #x0c)
(define nil-tag #x14)
(define eof-tag #x1c)
(define undefined-tag #x24)
(define dead-tag #x2c)
(define guard-tag #x34)
