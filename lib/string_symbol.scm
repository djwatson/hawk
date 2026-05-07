(import (scheme base) (prefix (hawk sys) sys:) (srfi 69))

;; The compiler fills this in with an alist of all interned symbols.
(define symbol-table symbol-table)

(define (ensure-symbol-hash-table!)
  (cond
   ((hash-table? symbol-table) symbol-table)
   ((list? symbol-table)
    (let ((table (alist->hash-table symbol-table string=? string-hash)))
      (set! symbol-table table)
      table))
   (else
    (error "Bad symbol table:" symbol-table))))

(define (string->symbol string)
  (let* ((table (ensure-symbol-hash-table!))
         (existing (hash-table-ref/default table string #f)))
    (if existing
        existing
        (let* ((new-name (string-copy string))
               (cell (sys:ALLOC (* 8 5) 6)))
          (sys:STORE cell new-name 0)
          ;(sys:STORE cell undefined-tag 1) ;; DONE IN VM/JIT NOW since we can't write tags
          (sys:STORE cell 0 2)
          (sys:STORE cell 0 3)
          (hash-table-set! table new-name cell)
          cell))))
