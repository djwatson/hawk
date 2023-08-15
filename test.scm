(define v 10)
(do ((i 0 (+ i 1)))
    ((= i 300))
  (set! v 20)
  )
(display v)

