(define (tak x y z)
  (if (< y x)
      (tak (tak (- x 1) y z)
	   (tak (- y 1) z x)
	   (tak (- z 1) x y))
      z))
;;(tak 9 6 3)
;;(tak 18 12 6)
;;(tak 27 18 9)
(display (tak 40 20 11))





