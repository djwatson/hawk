(import (scheme base) (prefix (hawk sys) sys:))

;; The compiler fills this in with an alist of all interned symbols.
;; At first use we convert to a grow-only string-keyed hash table.
;; layout: (count . #(bucket ...))
(define symbol-table symbol-table)

(define (string-hash s bound)
  (sys:FOREIGN_CALL '(uint64 "SCM_STRING_HASH" (string int32)) s bound))

;; There's a custom hash table here due to bootstrapping issues.
;; If we delay upgrade from alist to hashtable until after bootstrap loads the
;; final srfi -69, we could probably use srfi 69 directly.

(define (maybe-grow-hash-table! table)
  (let* ((count (car table)) (buckets (cdr table)) (old-size (vector-length buckets)))
    (when (>= count old-size)
      (let* ((new-size (* 2 old-size)) (new-buckets (make-vector new-size '())))
        (do ((i 0 (+ i 1)))
             ((>= i old-size))
             (for-each (lambda (entry)
                         (let ((h (string-hash (car entry) new-size)))
                           (vector-set! new-buckets h (cons entry (vector-ref new-buckets h)))))
                       (vector-ref buckets i)))
        (set-cdr! table new-buckets)))))

(define (ensure-symbol-hash-table!)
  (if (and (pair? symbol-table) (vector? (cdr symbol-table)))
      (cdr symbol-table)
      (let* ((size (max 64 (* 2 (length symbol-table)))) (buckets (make-vector size '())))
        (for-each (lambda (entry)
                    (let ((h (string-hash (car entry) size)))
                      (vector-set! buckets h (cons entry (vector-ref buckets h)))))
                  symbol-table)
        (set! symbol-table (cons (length symbol-table) buckets))
        buckets)))

(define (string->symbol string)
  (unless (string? string) (error "string->symbol: not a string"))
  (let* ((buckets (ensure-symbol-hash-table!))
         (size (vector-length buckets))
         (h (string-hash string size))
         (bucket (vector-ref buckets h))
         (existing (assoc string bucket string=?)))
    (if existing
        (cdr existing)
        (let* ((new-name (string-copy string)) (cell (sys:ALLOC (* 8 5) 6)))
          (sys:STORE cell new-name 0)
          (sys:STORE cell 0 2)
          (sys:STORE cell 0 3)
          (vector-set! buckets h (cons (cons new-name cell) bucket))
          (set-car! symbol-table (+ 1 (car symbol-table)))
          (maybe-grow-hash-table! symbol-table)
          cell))))
