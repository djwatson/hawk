;; (define v (make-vector 10))
;; (define g 0)
;; (do ((i 0 (+ i 1)))
;;     ((= i 300) 0)
;;   (set! g (+ g (vector-length v))))
;; (display g)
($write ($string-length ($symbol->string 'foo)) ($open 1 #f))

