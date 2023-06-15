(define (loop n sum)
  (let loop ((n n) (sum sum))
    (if (< n 0)
	sum
	(loop (- n 1) (+ n sum)))))

(display (loop 1000000000 0))
