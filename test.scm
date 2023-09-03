(define b '())
(do ((i 0 (+ 1 i)))
    ((= i 300000000))
  (set! b (make-string 0 #\a)))
;(write b )

