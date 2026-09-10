(define (arguments n)
  (let loop ((i n) (xs '()))
    (if (= i 0) xs (loop (- i 1) (cons (vector i) xs)))))

(define (check xs n)
  (let loop ((xs xs) (i 1))
    (if (null? xs)
        (unless (= i (+ n 1)) (error "Wrong argument count" i n))
        (begin
          (unless (= (vector-ref (car xs) 0) i)
            (error "Wrong argument" i (car xs)))
          (loop (cdr xs) (+ i 1))))))

(define (run n)
  (check (apply (lambda xs xs) (arguments n)) n)
  (check (apply (lambda (a b . xs) xs) #f #f (arguments n)) n))

(define (run-returns n)
  (check (call-with-values (lambda () (apply values (arguments n)))
                          (lambda xs xs))
         n)
  (check (call-with-values
           (lambda () (call/cc (lambda (k) (apply k (arguments n)))))
           (lambda xs xs))
         n)
  (check (call-with-values
           (lambda () (call/cc (lambda (k) (apply values (arguments n)))))
           (lambda xs xs))
         n))

(do ((i 0 (+ i 1))) ((= i 100)) (run 10) (run-returns 10))
(for-each run '(0 1 254 255 256 257 1000 100000))
(for-each run-returns '(0 1 254))
(display "ok")
(newline)
