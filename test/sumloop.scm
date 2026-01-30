(import (scheme r5rs) (scheme write))

;;; SUMLOOP -- One of the Kernighan and Van Wyk benchmarks.

;;; LC NOTE : Can't compute more because of heap/stack overflow

(define sum 0)

(define (tail-rec-aux i n)
  (if (< i n) (begin (set! sum (+ sum 1)) (tail-rec-aux (+ i 1) n)) sum))

(define (tail-rec-loop n) (set! sum 0) (tail-rec-aux 0 n) sum)

(set! sum 0)
(define (do-loop i n)
  (if (>= i n) sum (begin (set! sum (+ sum 1)) (do-loop (+ i 1) n))))
(display (do-loop 0 1000000000))

;0
;1
;10
;50
;100


