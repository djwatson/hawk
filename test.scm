(define (foo n) (let loop ((i n) (j 2))
		  (if (= i 0)
		      j
		      (loop (+ i -1) (if (> j 6553500) 1 (* j 3))))))

(display (foo 400))
(display (foo 1))

