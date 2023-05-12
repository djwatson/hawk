;; These have to match memory_layout.scm and types.h.
;; (define (number? x) (or (fixnum? x) (flonum? x)))
;; (define (flonum? x) ($guard x 2))
;; (define (fixnum? x) ($guard x 0))
;; (define (null? x) ($guard x 23))
;; (define (boolean? x) ($guard x 7))
;; (define (char? x) ($guard x #b00001111))
;; (define (pair? x) ($guard x 3))
;; (define (procedure? x) ($guard x 5))
;; (define (symbol? x) ($guard x 4))
;; (define (vector? x) ($guard x 17))
;; (define (string? x) ($guard x 9))
;; (define (port? x) ($guard x #b011001))
;; (define (+ a b) ($+ a b))
;; (define (- a b) ($- a b))
;; (define (* a b) ($* a b))
;; (define (< a b) ($< a b))
;; (define (not a) (if a #f #t))
;; (define (> a b) (not (or ($= a b) ($< a b))))

(define x 2)

(set! x 4)
x



