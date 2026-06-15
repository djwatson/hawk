;;; The Computer Language Benchmarks Game
;;; http://shootout.alioth.debian.org/
;;;
;;; contributed by Anthony Borla
;;; modified by Graham Fawcett

;;-----------------------------------------------------------------------------
;; use vector to implement body type instead of record for LC
(define (make-body x y z vx vy vz mass) (vector x y z vx vy vz mass))
(define (body-x body) (vector-ref body 0))
(define (body-y body) (vector-ref body 1))
(define (body-z body) (vector-ref body 2))
(define (body-vx body) (vector-ref body 3))
(define (body-vy body) (vector-ref body 4))
(define (body-vz body) (vector-ref body 5))
(define (body-mass body) (vector-ref body 6))
(define (body-x-set! body v) (vector-set! body 0 v))
(define (body-y-set! body v) (vector-set! body 1 v))
(define (body-z-set! body v) (vector-set! body 2 v))
(define (body-vx-set! body v) (vector-set! body 3 v))
(define (body-vy-set! body v) (vector-set! body 4 v))
(define (body-vz-set! body v) (vector-set! body 5 v))
(define (body-mass-set! body v) (vector-set! body 6 v))
;;-----------------------------------------------------------------------------

;; define planetary masses, initial positions & velocity

(define +pi+ 3.14159)
(define +days-per-year+ 365.24)

(define +solar-mass+ (* 4 +pi+ +pi+))

;(define-record body x y z vx vy vz mass)

(define *sun* (make-body 0.0 0.0 0.0 0.0 0.0 0.0 +solar-mass+))

(define *jupiter*
  (make-body 4.84143
             -1.16032
             -0.103622
             (* 0.00166008 +days-per-year+)
             (* 0.00769901 +days-per-year+)
             (* -6.9046e-05 +days-per-year+)
             (* 0.000954792 +solar-mass+)))

(define *saturn*
  (make-body 8.34337
             4.1248
             -0.403523
             (* -0.00276743 +days-per-year+)
             (* 0.00499853 +days-per-year+)
             (* 2.30417e-05 +days-per-year+)
             (* 0.000285886 +solar-mass+)))

(define *uranus*
  (make-body 12.8944
             -15.1112
             -0.223308
             (* 0.0029646 +days-per-year+)
             (* 0.00237847 +days-per-year+)
             (* -2.9659e-05 +days-per-year+)
             (* 4.36624e-05 +solar-mass+)))

(define *neptune*
  (make-body 15.3797
             -25.9193
             0.179259
             (* 0.00268068 +days-per-year+)
             (* 0.00162824 +days-per-year+)
             (* -9.51592e-05 +days-per-year+)
             (* 5.15139e-05 +solar-mass+)))

;; -------------------------------
(define (offset-momentum system)
  (let loop-i ((i system) (px 0.0) (py 0.0) (pz 0.0))
    (if (null? i)
        (begin
          (body-vx-set! (car system) (/ (- px) +solar-mass+))
          (body-vy-set! (car system) (/ (- py) +solar-mass+))
          (body-vz-set! (car system) (/ (- pz) +solar-mass+)))
        (loop-i (cdr i)
                (+ px (* (body-vx (car i)) (body-mass (car i))))
                (+ py (* (body-vy (car i)) (body-mass (car i))))
                (+ pz (* (body-vz (car i)) (body-mass (car i))))))))

;; -------------------------------
(define (energy system)
  (let loop-o ((o system) (e 0.0))
    (if (null? o)
        e
        (let ((e
                 (+ e
                    (* 0.5
                       (body-mass (car o))
                       (+ (* (body-vx (car o)) (body-vx (car o)))
                          (* (body-vy (car o)) (body-vy (car o)))
                          (* (body-vz (car o)) (body-vz (car o))))))))

          (let loop-i ((i (cdr o)) (e e))
            (if (null? i)
                (loop-o (cdr o) e)
                (let* ((dx (- (body-x (car o)) (body-x (car i))))
                       (dy (- (body-y (car o)) (body-y (car i))))
                       (dz (- (body-z (car o)) (body-z (car i))))
                       (distance (sqrt (+ (* dx dx) (* dy dy) (* dz dz)))))
                  (let ((e (- e (/ (* (body-mass (car o)) (body-mass (car i))) distance))))
                    (loop-i (cdr i) e)))))))))

;; -------------------------------
(define (advance system dt)
  (let loop-o ((o system))
    (if (not (null? o))
        (begin
          (let loop-i ((i (cdr o)))
            (if (not (null? i))
                (let* ((o1 (car o))
                       (i1 (car i))
                       (dx (- (body-x o1) (body-x i1)))
                       (dy (- (body-y o1) (body-y i1)))
                       (dz (- (body-z o1) (body-z i1)))
                       (distance (sqrt (+ (* dx dx) (* dy dy) (* dz dz))))
                       (mag (/ dt (* distance distance distance)))
                       (dxmag (* dx mag))
                       (dymag (* dy mag))
                       (dzmag (* dz mag))
                       (om (body-mass o1))
                       (im (body-mass i1)))
                  (body-vx-set! o1 (- (body-vx o1) (* dxmag im)))
                  (body-vy-set! o1 (- (body-vy o1) (* dymag im)))
                  (body-vz-set! o1 (- (body-vz o1) (* dzmag im)))
                  (body-vx-set! i1 (+ (body-vx i1) (* dxmag om)))
                  (body-vy-set! i1 (+ (body-vy i1) (* dymag om)))
                  (body-vz-set! i1 (+ (body-vz i1) (* dzmag om)))
                  (loop-i (cdr i)))))
          (loop-o (cdr o)))))

  (let loop-o ((o system))
    (if (not (null? o))
        (let ((o1 (car o)))
          (body-x-set! o1 (+ (body-x o1) (* dt (body-vx o1))))
          (body-y-set! o1 (+ (body-y o1) (* dt (body-vy o1))))
          (body-z-set! o1 (+ (body-z o1) (* dt (body-vz o1))))
          (loop-o (cdr o))))))

;; -------------------------------

(define (main n)
  (let ((system (list *sun* *jupiter* *saturn* *uranus* *neptune*)))
    (offset-momentum system)
    (let ((before (energy system)))
      (do ((i 1 (+ i 1))) ((< n i)) (advance system 0.01))
      (let ((after (energy system))) (cons before after)))))

(define (pp x) (display x) (newline))
(let ((r (main 50000000)))
  (pp (< (+ 0.169075 (car r)) 1e-09))
  (pp (< (+ 0.169086 (cdr r)) 1e-09)))

;#t
;#t

