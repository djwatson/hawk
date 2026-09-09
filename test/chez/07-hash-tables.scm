(import (scheme base) (scheme write) (srfi 69))

(define pass-count 0)
(define fail-count 0)

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (equal? result expected)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected ")
             (write expected)
             (display " got ")
             (write result)
             (newline)))))))

;; Basic creation
(let ((ht (make-hash-table)))
  (check (hash-table? ht) #t)
  (check (hash-table-size ht) 0))

;; set! and ref
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (check (hash-table-ref ht 'a) 1)
  (check (hash-table-size ht) 1))

;; Multiple entries
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'b 2)
  (hash-table-set! ht 'c 3)
  (check (hash-table-ref ht 'a) 1)
  (check (hash-table-ref ht 'b) 2)
  (check (hash-table-ref ht 'c) 3)
  (check (hash-table-size ht) 3))

;; Overwrite
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'a 2)
  (check (hash-table-ref ht 'a) 2)
  (check (hash-table-size ht) 1))

;; exists?
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (check (hash-table-exists? ht 'a) #t)
  (check (hash-table-exists? ht 'b) #f))

;; delete!
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'b 2)
  (hash-table-delete! ht 'a)
  (check (hash-table-exists? ht 'a) #f)
  (check (hash-table-ref ht 'b) 2)
  (check (hash-table-size ht) 1))

;; Delete non-existent key
(let ((ht (make-hash-table)))
  (hash-table-delete! ht 'nonexistent)
  (check (hash-table-size ht) 0))

;; ref/default
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (check (hash-table-ref/default ht 'a 0) 1)
  (check (hash-table-ref/default ht 'b 0) 0))

;; update!
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-update! ht 'a (lambda (v) (+ v 1)))
  (check (hash-table-ref ht 'a) 2))

;; update!/default
(let ((ht (make-hash-table)))
  (hash-table-update!/default ht 'a (lambda (v) (+ v 1)) 0)
  (check (hash-table-ref ht 'a) 1))

;; keys, values, entries
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'b 2)
  (check (length (hash-table-keys ht)) 2)
  (check (length (hash-table-values ht)) 2))

;; walk
(let ((ht (make-hash-table))
      (seen '()))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'b 2)
  (hash-table-walk ht (lambda (k v) (set! seen (cons (cons k v) seen))))
  (check (length seen) 2))

;; alist->hash-table and hash-table->alist
(let ((alist '((a . 1) (b . 2) (c . 3)))
      (ht (alist->hash-table '((a . 1) (b . 2) (c . 3)))))
  (check (hash-table-ref ht 'a) 1)
  (check (hash-table-ref ht 'b) 2)
  (check (hash-table-ref ht 'c) 3)
  (check (hash-table-size ht) 3))

;; String keys
(let ((ht (make-hash-table)))
  (hash-table-set! ht "hello" 42)
  (check (hash-table-ref ht "hello") 42))

;; Numeric keys
(let ((ht (make-hash-table)))
  (hash-table-set! ht 1 "one")
  (hash-table-set! ht 2 "two")
  (check (hash-table-ref ht 1) "one")
  (check (hash-table-ref ht 2) "two"))

;; hash procedure
(check (number? (hash 'test)) #t)
(check (number? (hash "test")) #t)

;; string-hash
(check (number? (string-hash "hello")) #t)
(check (= (string-hash "hello") (string-hash "hello")) #t)

;; copy
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (let ((ht2 (hash-table-copy ht)))
    (hash-table-set! ht2 'b 2)
    (check (hash-table-ref ht 'a) 1)
    (check (hash-table-exists? ht 'b) #f)
    (check (hash-table-ref ht2 'a) 1)
    (check (hash-table-ref ht2 'b) 2)))

;; fold
(let ((ht (make-hash-table)))
  (hash-table-set! ht 'a 1)
  (hash-table-set! ht 'b 2)
  (let ((sum (hash-table-fold ht (lambda (k v acc) (+ v acc)) 0)))
    (check sum 3)))

;; Result
(newline)
(display "Hash tables: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
