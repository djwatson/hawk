(define (fibc x k)
  (if (< x 2)
      (k x)
      (k (+ (call-with-current-continuation
	    (lambda (c) (fibc (- x 1) c)))
	   (call-with-current-continuation
	    (lambda (c) (fibc (- x 2) c)))))))

(display (fibc 30 (lambda (v) v)))


