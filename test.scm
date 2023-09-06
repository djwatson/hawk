(define (fibc x k)
  (if (< x 2)
      (k x)
      (k (+ (call-with-current-continuation
	    (lambda (c) (fibc (- x 1) c)))
	   (call-with-current-continuation
	    (lambda (c) (fibc (- x 2) c)))))))

(display (fibc 30 (lambda (v) v)))

;; (define (foo x)
;;   (if (= x 0) 0
;;       (begin
;; 	(call-with-current-continuation (lambda (cont) (cont 0)))
;; 	;($write #\. current-output-port-internal)
;; 	(foo (- x 1)))))

;; (foo 100000000)

