(let ((c (make-string 300 #\a))
      (str (make-string 300 #\b)))
  (let loop ((i 0) (j 0))
    (if (< i 300)
	(begin
	  (string-set! c j (string-ref str i))
	  (loop (+ i 1) (+ j 1)))))
  (display c))

