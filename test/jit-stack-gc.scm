(import (scheme base) (scheme write) (scheme process-context))

;; Keep caller frames live while allocating below the JIT entry frame.
(define (rational-down n x)
  (if (= n 0)
      x
      (+ (rational-down (- n 1) (+ x 1/3)) x)))

;; Returning through traces also boxes snapshot values.
(define (flonum-down n x)
  (if (= n 0)
      x
      (+ (flonum-down (- n 1) (+ x 1.0)) x)))

(do ((i 0 (+ i 1))) ((= i 100))
  (unless (and (= (rational-down 500 1/3) 41917)
               (= (flonum-down 500 1.0) 125751.0))
    (display "jit-stack-gc failed\n")
    (exit 1)))
(display "jit-stack-gc passed\n")
