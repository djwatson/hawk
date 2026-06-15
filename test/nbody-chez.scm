#!/usr/bin/env scheme-script
;; chezfl-nbody.scm
;; NBODY exercise by  http://bit.ly/41zBI5a
;; compile: scheme> (parameterize ((optimize-level 3)) (compile-program "chezfl-nbody.scm"))
;;     run: $ ./chezfl-nbody.scm <n-iterations>

(import (chezscheme))

(module
 (take-energy)

 (define PI (* 4.0 (atan 1)))
 (define SOLAR-MASS (* 4 PI PI))
 (define DAYS-PER-YEAR 365.24)
 (define-syntax dpe (syntax-rules () ((_ v) (* v DAYS-PER-YEAR))))
 (define-syntax slr (syntax-rules () ((_ m) (* m SOLAR-MASS))))

 (define-syntax dotimes (syntax-rules () ((_ n body ...) (do ((i_ n (fx1- i_))) ((fxzero? i_)) body ...))))
 (define-syntax subn! (syntax-rules () ((_ what withs) (set! what (fl- what withs)))))
 (define-syntax addn! (syntax-rules () ((_ what withs) (set! what (fl+ what withs)))))

 (define (take-energy n)
   (define bodies
     (flvector
      SOLAR-MASS 0.0 0.0 0.0 0.0 0.0 0.0  0.0 0.0 0.0 0.0   ;; SUN
      (slr 9.54791938424326609e-04) 4.84143144246472090e+00 -1.16032004402742839e+00 -1.03622044471123109e-01 (dpe 1.66007664274403694e-03) (dpe 7.69901118419740425e-03) (dpe -6.90460016972063023e-05) 0.0 0.0 0.0 0.0
      (slr 2.85885980666130812e-04) 8.34336671824457987e+00 4.12479856412430479e+00 -4.03523417114321381e-01 (dpe -2.76742510726862411e-03) (dpe 4.99852801234917238e-03) (dpe 2.30417297573763929e-05) 0.0 0.0 0.0 0.0
      (slr 4.36624404335156298e-05) 1.28943695621391310e+01 -1.51111514016986312e+01 -2.23307578892655734e-01 (dpe 2.96460137564761618e-03) (dpe 2.37847173959480950e-03) (dpe -2.96589568540237556e-05) 0.0 0.0 0.0 0.0
      (slr 5.15138902046611451e-05) 1.53796971148509165e+01 -2.59193146099879641e+01 1.79258772950371181e-01 (dpe 2.68067772490389322e-03) (dpe 1.62824170038242295e-03) (dpe -9.51592254519715870e-05) 0.0 0.0 0.0 0.0
      ))
   (define-syntax body-size (identifier-syntax 11))
   (define-syntax bodies-len (identifier-syntax 55)) ;; (1)
   ;;(define bodies-len (flvector-length bodies))    ;; (2)
   (define-syntax dt (identifier-syntax 0.01))

   (define-syntax let-attr
     (syntax-rules () ((_ ((a ix offset) ...) body ...)
                       (let-syntax ((a (identifier-syntax  ;; (3)
                                        (_ (flvector-ref bodies (fx+ ix offset)))
                                        ((set! _ val) (flvector-set! bodies (fx+ ix offset) val)))) ...)
                         body ...))))

   (define-syntax ^2 (syntax-rules () ((_ x) (fl* x x))))
   (define-syntax sum^2 (syntax-rules () ((_ x y z) (fl+ (^2 x) (^2 y) (^2 z)))))
   (define (dsqt v) (fl* v (flsqrt v)))
   (define E 0.0)

   (dotimes
    n
    (do ((i 0 (fx+ i body-size)))
        ((fx= i bodies-len))
      (do ((j (fx+ i body-size) (fx+ j body-size)))
          ((fx= j bodies-len))
        (let-attr
         ((massi i 0) (Xi i 1) (Yi i 2) (Zi i 3)
          (massj j 0) (Xj j 1) (Yj j 2) (Zj j 3)
          (VXi i 4) (VYi i 5) (VZi i 6)
          (VXj j 4) (VYj j 5) (VZj j 6)
          (dx j 7) (dy j 8) (dz j 9)
          (mag j 10))
         (set! dx (fl- Xi Xj))
         (set! dy (fl- Yi Yj))
         (set! dz (fl- Zi Zj))
         (set! mag (fl/ dt (dsqt (sum^2 dx dy dz))))

         (subn! VXi (fl* dx massj mag))
         (subn! VYi (fl* dy massj mag))
         (subn! VZi (fl* dz massj mag))
         (addn! VXj (fl* dx massi mag))
         (addn! VYj (fl* dy massi mag))
         (addn! VZj (fl* dz massi mag))
         )))
    (do ((i 0 (fx+ i body-size)))
        ((fx= i bodies-len))
      (let-attr
       ((X i 1) (Y i 2) (Z i 3)
        (VX i 4) (VY i 5) (VZ i 6))
       (addn! X (fl* dt VX))
       (addn! Y (fl* dt VY))
       (addn! Z (fl* dt VZ)))))

   (do ((i 0 (fx+ i body-size)))
       ((fx= i bodies-len) E)
     (let-attr
      ((massi i 0)
       (VX i 4)
       (VY i 5)
       (VZ i 6))
      (addn! E (fl* 0.5 massi (sum^2 VX VY VZ)))
      (do ((j (fx+ i body-size) (fx+ body-size j)))
          ((fx= j bodies-len))
        (let-attr
         ((Xi i 1) (Yi i 2) (Zi i 3)
          (Xj j 1) (Yj j 2) (Zj j 3) (massj j 0))
         (subn! E (fl/ (fl* massi massj)
                       (flsqrt (sum^2
                                (fl- Xi Xj)
                                (fl- Yi Yj)
                                (fl- Zi Zj))))))
        )))
   )
 ) ;; end-of-module

(define (tf t)
  (+ (time-second t) (* 1e-9 (time-nanosecond t))))

(cond (#t
       (let* ((n (string->number "50000000"))
              (st (current-time 'time-monotonic))
              (e (take-energy n))
              (et (current-time 'time-monotonic)))
         (printf "~,9f  per ~,3f sec on ~a ~%" e (tf (time-difference et st)) n)))
      (else (printf "Usage: ~a <n-iterations>~%" (car (command-line)))))


;;; i5 1035G1 1GHz  50000000 at ~ 6.7s vs c ffi'ed nbody 2.3s
