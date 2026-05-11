(import (scheme case-lambda) (scheme base) (scheme write) (prefix (hawk sys) sys:) (srfi 69))

(define (check-shared? shared x port)
  (let ((seen (hash-table-ref/default (cdr shared) x #f)))
    (cond
      ((integer? seen) (display "#" port) (display seen port) (display "#" port) #t)
      (seen
        (display "#" port)
        (display (car shared) port)
        (hash-table-set! (cdr shared) x (car shared))
        (set-car! shared (+ (car shared) 1))
        (display "=" port)
        #f)
      (else #f))))

(define (extract-shared-objects x cyclic-only?)
  (let ((seen (make-hash-table eq?)))
    ;; find shared references
    (let find ((x x))
      ;; only interested in pairs, vectors and records
      (when (or (pair? x) (vector? x))
        ;; increment the count
        (hash-table-update!/default seen x (lambda (n) (+ n 1)) 0)
        ;; walk if this is the first time
        (cond
          ((> (hash-table-ref seen x) 1))
          ((pair? x) (find (car x)) (find (cdr x)))
          ((vector? x)
            (do ((i 0 (+ i 1))) ((= i (vector-length x))) (find (vector-ref x i)))))
        ;; delete if this shouldn't count as a shared reference
        (if (and cyclic-only? (<= (hash-table-ref/default seen x 0) 1))
            (hash-table-delete! seen x))))
    ;; extract shared references
    (let ((res (make-hash-table eq?)))
      (hash-table-walk seen (lambda (k v) (if (> v 1) (hash-table-set! res k #t))))
      res)))

(define (write-all arg port type)
  (let ((shared (cons 0 (extract-shared-objects arg (not (eq? type 'shared))))))
    (let write ((arg arg) (port port))
      (cond
        ((null? arg) (display "()" port))
        ((pair? arg)
          (unless (check-shared? shared arg port)
            (write-char #\( port)
            (write (car arg) port)
            (let write-cdr ((arg (cdr arg)))
              (cond
                ((and (pair? arg) (not (hash-table-ref/default (cdr shared) arg #f)))
                  (display " " port)
                  (write (car arg) port)
                  (write-cdr (cdr arg)))
                ((null? arg) (display ")" port))
                (else (display " . " port) (write arg port) (display ")" port))))))
        ((vector? arg)
          (unless (check-shared? shared arg port)
            (display "#" port)
            (write (vector->list arg) port)))
        ((char? arg)
          (case arg
            ((#\newline) (display "#\\newline" port))
            ((#\tab) (display "#\\tab" port))
            ((#\space) (display "#\\space" port))
            ((#\return) (display "#\\return" port))
            ((#\alarm) (display "#\\alarm" port))
            ((#\backspace) (display "#\\backspace" port))
            ((#\delete) (display "#\\delete" port))
            ((#\escape) (display "#\\escape" port))
            ((#\null) (display "#\\null" port))
            (else (display "#\\" port) (display arg port))))
        ((string? arg)
          (display "\"" port)
          (for-each (lambda (chr)
                      (case chr
                        ((#\") (display "\\\"" port))
                        ((#\\) (display "\\\\" port))
                        ((#\newline) (display "\\n" port))
                        ((#\tab) (display "\\t" port))
                        ((#\return) (display "\\r" port))
                        ((#\alarm) (display "\\a" port))
                        ((#\backspace) (display "\\b" port))
                        ((#\delete) (display "\\x7F;" port))
                        ((#\escape) (display "\\x1B;" port))
                        ((#\null) (display "\\x00;" port))
                        (else (display chr port))))
                    (string->list arg))
          (display "\"" port))
        (else (display arg port))))))

(define write
  (case-lambda
    ((arg) (write arg (current-output-port)))
    ((arg port) (write-all arg port 'write))))

(define write-simple
  (case-lambda
    ((arg) (write-simple arg (current-output-port)))
    ((arg port) (write-all arg port 'simple))))

(define write-shared
  (case-lambda
    ((arg) (write-shared arg (current-output-port)))
    ((arg port) (write-all arg port 'shared))))


