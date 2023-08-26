;; (define-syntax case-lambda
;;   (syntax-rules ()
;;     ((_ (args body ...) ...)
;;      ($case-lambda (lambda args body ...) ...))))

;; (define (id x) x)

;; (define for-each2
;;   (case-lambda
;;    ((proc lst) (if (not (null? lst))
;;       (begin
;; 	(proc (car lst))
;; 	(for-each2 proc (cdr lst)))))
;;    ((proc lst1 lst2) (if (and  (not (null? lst1)) (not (null? lst2)))
;;       (begin
;; 	(proc (car lst1) (car lst2))
;; 	(for-each2 proc (cdr lst1) (cdr lst2)))))))
;; (define l '(1 2 3))
;; (do ((i 0 (+ i 1)))
;;     ((= i 300))
;;   (for-each2 id l))

(do ((i 0 (+ i 1)))
    ((= i 300))
  (write i))
