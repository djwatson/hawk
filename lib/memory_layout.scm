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
;; ptr-tagged objects
;; Bottom bits must be '001'
;; First 8 bytes are always the tag.
(define string-tag #b001001)
(define port-tag #b011001)
(define box-tag #b100001)
(define cont-tag #b101001)
;; literals, using literal-tag (so bottom 3 bits must be 0b111)
(define true-rep #x00000104)
(define false-rep #x00000004)
(define char-tag #b00001100)
(define nil-tag #b00010100)
(define eof-tag #b00011100)
(define undefined-tag #b00100100)
