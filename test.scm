
(define-syntax case-lambda
  (syntax-rules ()
    ((_ (args body ...) ...)
     ($case-lambda (lambda args body ...) ...))))
(define foo
  (case-lambda
    ((x . rest)
     (if (= x 0) 0
	 (begin
	   ;($write rest current-output-port-internal)
	   (+ (car rest) (foo (- x 1) (car rest))))))))

(display (foo 1000 2))
(newline)
(define (bar x)
  (if (= x 0) 0
      (begin
	(foo 1 1 2 3)
	(bar (- x 1)))))
(display (bar 1000))
