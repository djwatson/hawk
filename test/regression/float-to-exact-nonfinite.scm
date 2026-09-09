;; Keep the conversion site hot before changing its input to a nonfinite value.
(define (convert-loop finite nonfinite)
  (let loop ((i 0) (x finite))
    (exact x)
    (if (< i 2000)
        (loop (+ i 1) (if (= i 1999) nonfinite x)))))

(define (check finite nonfinite)
  (if (not (guard (e ((error-object? e) #t))
             (convert-loop finite nonfinite)
             #f))
      (error "exact accepted a nonfinite number")))

(for-each
  (lambda (x)
    (check 1.0 x)
    (check 1.5 x))
  (list +inf.0 -inf.0 +nan.0))
(for-each
  (lambda (x)
    (check 1.5+2.5i (make-rectangular x 2.5))
    (check 1.5+2.5i (make-rectangular 1.5 x)))
  (list +inf.0 -inf.0 +nan.0))
(display "nonfinite-exact-ok")
(newline)
