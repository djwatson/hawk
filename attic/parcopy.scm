;; serialize parallel copy implementation, based on
;; https://github.com/pfalcon/parcopy
;; Allows fan out
;; Does *not* use tmp reg, uses xchg.
;; This is fine for zen, maybe slightly slower for intel.
;; (import (srfi 151))
;; (import (scheme cxr))
;; (import (scheme base))
;; (import (srfi 1))
;; (include "set.scm")
;; (include "third-party/hamt.scm")

(define-syntax pop!
  (syntax-rules ()
    ((_ var)
      (let ((val (car var)))
        (set! var (cdr var)) val))))

(define (serialize-parallel-copy moves)
  (define res '())
  (define ready '())
  ;; reversed moves
  (define rmoves (make-hamt))
  ;; original symbolic location name to real loc
  (define loc (make-hamt))
  ;; reverse loc
  (define rloc (make-hamt))
  ;; Check for multiple moves to same dest error
  (for move moves
    (if (hamt/get rmoves (cadr move) #f) 
      (error "Multiple moves to same dest"))
    (hamt/insert!
      rmoves
      (second move)
      (first move))
    (hamt/insert! loc (first move) (first move))
    (hamt/insert! rloc (first move) (first move))
    (if (not (assoc (second move) moves)) 
      (push! ready (second move))))
  (do ()
      ((hamt-empty? rmoves))
    (do ()
        ((not (pair? ready)))
      (let ((r (pop! ready)))
        (when (hamt/get rmoves r #f) 
          (let ((rmove (hamt/find loc (hamt/find rmoves r))))
            (push! res (list 'mov rmove r))
            (hamt/insert! loc rmove r)
            (hamt/insert! rloc r rmove)
            (hamt/delete! rmoves r)
            (push! ready rmove)))))
    ;; Fall through from above loop, recheck empty rmoves
    (when (not (hamt-empty? rmoves)) 
      (let* ((k
               (hamt-fold
                 rmoves
                 (lambda (init k v) 
                   k)
                 #f))
             (to k)
             (rfrom (hamt/find rmoves k))
             (from (hamt/find loc rfrom)))
        (hamt/delete! rmoves k)
        (when (not (equal? from to)) 
          (push! res (list 'xchg from to))
          (let ((rto (hamt/find rloc to)))
            (hamt/insert! loc rto from)
            (hamt/insert! rloc from rto))))))
  (reverse! res))

;; (define (test args res)
;;   (let ((r (serialize-parallel-copy args)))
;;     (when (not (equal? res r)) 
;;       (display "FAIL, got:")
;;       (display r)
;;       (display "expected:")
;;       (display res)
;;       (newline))))
;; ;; Trivial case
;; (test
;;   '((1 0) (2 1) (3 2))
;;   '((mov 1 0) (mov 2 1) (mov 3 2)))
;; ;; Self loop optimized away
;; (test '((0 0)) '())
;; ;; Loop with 2
;; (test '((0 1) (1 0)) '((xchg 0 1)))
;; ;; Loop with 3
;; (test
;;   '((2 1) (3 2) (1 3))
;;   '((xchg 1 3) (xchg 2 1)))
;; ;; Loop with 4
;; (test
;;   '((2 1) (3 2) (1 4) (4 3))
;;   '((xchg 4 3) (xchg 2 1) (xchg 4 2)))
;; ;; Loop with 5
;; (test
;;   '((2 1) (3 2) (1 4) (4 5) (5 3))
;;   '((xchg 5 3) (xchg 2 1) (xchg 5 2) (xchg 5 4)))
;; ;; Two loops of 2
;; (test
;;   '((1 0) (0 1) (2 3) (3 2))
;;   '((xchg 2 3) (xchg 0 1)))
;; ;; simple fan out
;; (test '((1 2) (1 3)) '((mov 1 3) (mov 3 2)))
;; ;; more complex fan out
;; (test
;;   '((1 2) (2 3) (3 1) (3 4))
;;   '((mov 3 4) (mov 2 3) (mov 1 2) (mov 4 1)))
;; ;; Overlapping tmp
;; (test
;;   '((3 1) (1 3) (2 4))
;;   '((mov 2 4) (xchg 1 3)))
