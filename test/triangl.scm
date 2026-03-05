;;; TRIANGL -- Board game benchmark.
(import (except (scheme base)
                vector-length
                make-vector
                vector-ref
                vector-set!
                list->vector
                length
                vector->list
                cons
                car
                cdr
                pair?
                not) (only (scheme r5rs) exact->inexact) (scheme write) (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))

(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))

(define (not a) (if a #f #t))
(define (pair? a) (sys:GUARD a 3))
(define (vector-length vec) (sys:LOAD vec 0))
(define (make-vector len)
  (let ((vec (sys:ALLOC (+ 16 (* len 8)) 7))) (sys:STORE vec len 0) vec))
(define (vector-ref vec idx) (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val) (sys:STORE vec val (+ 1 idx)))
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))
(define (length a)
  (let loop ((len 0) (a a)) (if (pair? a) (loop (+ len 1) (cdr a)) len)))
(define (vector->list vec)
  (let loop ((i (vector-length vec)) (l '()))
    (if (= i 0) l (loop (- i 1) (cons (vector-ref vec (- i 1)) l)))))

(define *board* (list->vector '(1 1 1 1 1 0 1 1 1 1 1 1 1 1 1 1)))

(define *sequence* (list->vector '(0 0 0 0 0 0 0 0 0 0 0 0 0 0)))

(define *a*
  (list->vector '(1 2 4 3 5 6 1 3 6 2 5 4 11 12 13 7 8 4 4 7 11 8 12 13 6 10 15 9 14 13 13 14 15 9
                  10 6 6)))

(define *b*
  (list->vector '(2 4 7 5 8 9 3 6 10 5 9 8 12 13 14 8 9 5 2 4 7 5 8 9 3 6 10 5 9 8 12 13 14 8 9 5 5)))

(define *c*
  (list->vector '(4 7 11 8 12 13 6 10 15 9 14 13 13 14 15 9 10 6 1 2 4 3 5 6 1 3 6 2 5 4 11 12 13 7
                  8 4 4)))

(define *answer* '())

(define (attempt i depth)
  (cond
    ((= depth 14)
      (set! *answer* (cons (cdr (vector->list *sequence*)) *answer*))
      #t)
    ((and (= 1 (vector-ref *board* (vector-ref *a* i)))
          (= 1 (vector-ref *board* (vector-ref *b* i)))
          (= 0 (vector-ref *board* (vector-ref *c* i))))
      (vector-set! *board* (vector-ref *a* i) 0)
      (vector-set! *board* (vector-ref *b* i) 0)
      (vector-set! *board* (vector-ref *c* i) 1)
      (vector-set! *sequence* depth i)
      (do ((j 0 (+ j 1)) (depth (+ depth 1))) ((or (= j 36) (attempt j depth)) #f))
      (vector-set! *board* (vector-ref *a* i) 1)
      (vector-set! *board* (vector-ref *b* i) 1)
      (vector-set! *board* (vector-ref *c* i) 0)
      #f)
    (else #f)))

(define (test i depth) (set! *answer* '()) (attempt i depth) (car *answer*))

;-----
(define (run n res) (if (= n 0) res (run (- n 1) (test 22 1))))
(display (run 50 0))
(display "\n")

;(22 34 31 15 7 1 20 17 25 6 5 13 32)


