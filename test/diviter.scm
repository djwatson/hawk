(define (create-n n) (do ((n n (- n 1)) (a '() (cons '() a))) ((= n 0) a)))

(define (iterative-div2 l)
  (do ((l l (cddr l)) (a '() (cons (car l) a))) ((null? l) a)))

(define (run x ll out) (if (= x 0) out (run (- x 1) ll (iterative-div2 ll))))

(let ((ll (create-n 1000))) (display (length (run 1000000 ll 0))))


