(define g "short")
(do ((i 0 (+ i 1)) (foo "bar"))
    ((= i 300))
  (if (vector? (if (< i 200) "t" '#(1 2 3) ))
      ($write "abort" (current-output-port))))


;; (define g "short")
;; (do ((i 0 (+ i 1)) (foo "bar"))
;;     ((= i 300))
;;   (if (vector? "test")
;;       ($write "abort" current-output-port-internal)))

