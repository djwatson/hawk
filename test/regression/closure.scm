(define (pp)
  (define (pp-expr) (style) max-call-head-width)
  (define (pp-do) pp-expr)
  (define max-call-head-width (* 4 4))
  (define (style) pp-do)

  (pp-expr))

(display (pp))


