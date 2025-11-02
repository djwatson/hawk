;; Unique steps:
;; - stack-load (48 uses)
;; - write-reg (30 uses)
;; - check-arity (14 uses)
;; - prepare-call (14 uses)
;; - call-dispatch (9 uses)
;; - build-rest-args (6 uses)
;; - compare-overflow (5 uses)
;; - jit-call-dispatch (4 uses)
;; - arith-overflow (3 uses)
;; - const-load (3 uses)
;; - load-field (2 uses)
;; - store-field (2 uses)
;; - adjust-pc-for-branch (1 use)
;; - advance-pc (1 use)
;; - alloc-closure (1 use)
;; - alloc-object (1 use)
;; - apply-build-args (1 use)
;; - apply-dispatch (1 use)
;; - arith-div (1 use)
;; - arith-mod (1 use)
;; - branch-if-false (1 use)
;; - call-ffi (1 use)
;; - callcc-capture (1 use)
;; - callcc-restore (1 use)
;; - capture-free-vars (1 use)
;; - char->integer (1 use)
;; - closure-get (1 use)
;; - convert-to-exact (1 use)
;; - convert-to-inexact (1 use)
;; - define-symbol (1 use)
;; - ensure-type (1 use)
;; - eq-compare (1 use)
;; - guard-type (1 use)
;; - halt (1 use)
;; - hotmap-check (1 use)
;; - int->char (1 use)
;; - io-write (1 use)
;; - jit-dispatch-loop (1 use)
;; - jump-loop (1 use)
;; - jump-relative (1 use)
;; - load-arg (1 use)
;; - load-loop-target (1 use)
;; - lookup-symbol (1 use)
;; - loop-noop (1 use)
;; - maybe-start-trace (1 use)
;; - mov (1 use)
;; - move-frame-for-loop (1 use)
;; - prepare-fcall (1 use)
;; - record-loop-entry (1 use)
;; - return-frame (1 use)
;; - tail-dispatch (1 use)
(import (scheme base) (scheme write) (srfi 28))

;; Opcodes in vm.c:
;; CONST, WRITE, LCALL, LCALLT, RET, KILL, ICFUNCV, ICFUNC, IFUNCV, IFUNC,
;; CFUNCV, CFUNC, FUNCV, FUNC, JCFUNCV, JCFUNC, JFUNCV, JFUNC, JLOOP,
;; CALLCC, CALLCC_RESUME, ARG, HALT, GUARD, ILOOP, LOOP, LOAD, LOAD_CHAR,
;; STORE, STORE_CHAR, INTEGER_CHAR, CHAR_INTEGER, APPLY, ALLOC, ADD,
;; SUB, FX_DIV, FX_MOD, FX_MUL, FX_LT, FX_LTE, FX_EQ, EQ, EXACT, INEXACT,
;; FL_ADD, FL_SUB, FL_MUL, FL_DIV, FL_MOD, FL_LT, FL_LTE, FL_GT, FL_GTE,
;; FL_EQ, CLOSURE, CLOSURE_GET, LOOKUP, DEFINE, IF, PHI, JMP, LJMP, FCALL.


;; 298 -- PROG-fib:
;; Consts:
;; 0: 2
;; 1: PROG-fib
;; 2: 1
;; 3: -1
;;
;; Code:
;; 0: 	FUNC           2
;; 1: 	KILL           0
;; 2: 	CONST          2	0	 ;; 2
;; 3: 	FX_LT          2	1	2
;; 4: 	IF             2	2	 ==> 6
;; 5: 	RET            1
;; 6: ==>	LOOKUP         3	1	 ;; PROG-fib
;; 7: 	CONST          4	2	 ;; 1
;; 8: 	SUB            4	1	4
;; 9: 	CONST          2	3	 ;; -1
;; 10: 	CLOSURE_GET    2	3	2
;; 11: 	LCALL          2	3
;; 12: 	LOOKUP         4	1	 ;; PROG-fib
;; 13: 	CONST          5	0	 ;; 2
;; 14: 	SUB            5	1	5
;; 15: 	CONST          3	3	 ;; -1
;; 16: 	CLOSURE_GET    3	4	3
;; 17: 	LCALL          3	3
;; 18: 	ADD            2	2	3
;; 19: 	RET            2

;; And loader:
;; 689: 	CONST          0	588	 ;; ($const-closure . 298)
;; 690: 	DEFINE         0	589	 ;; PROG-fib
;; 691: 	LOOKUP         1	44	 ;; display
;; 692: 	LOOKUP         3	589	 ;; PROG-fib
;; 693: 	CONST          4	590	 ;; 40
;; 694: 	CONST          2	284	 ;; -1
;; 695: 	CLOSURE_GET    2	3	2
;; 696: 	LCALL          2	3
;; 697: 	CONST          0	284	 ;; -1
;; 698: 	CLOSURE_GET    0	1	0
;; 699: 	LCALLT         0	3

;; So let's assume FIB needs: CONST FUNC FX_LT IF RET FX_SUB LOOKUP CLOSURE_GET LCALL LOOKUP 

(define operations
  (list
   `((name . "ALLOC")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (alloc-object v1 v2)
       (write-reg result)
     )))
   `((name . "APPLY")
     (steps . (
       (stack-load v1 callable)
       (stack-load v2 list)
       (apply-build-args)
       (apply-dispatch)
     )))
   `((name . "ARG")
     (steps . (
       (load-arg)
       (write-reg argument)
     )))
   `((name . "CALLCC")
     (steps . (
       (callcc-capture)
       (write-reg continuation)
     )))
   `((name . "CALLCC_RESUME")
     (steps . (
       (callcc-restore)
       (write-reg result)
     )))
   `((name . "CFUNC")
     (steps . (
       (prepare-call cfunc)
       (check-arity exact)
       (call-dispatch cfunc)
     )))
   `((name . "CFUNCV")
     (steps . (
       (prepare-call cfuncv)
       (check-arity variadic)
       (build-rest-args)
       (call-dispatch cfunc)
     )))
   `((name . "CHAR_INTEGER")
     (steps . (
       (stack-load v1 char)
       (char->integer)
       (write-reg fixnum)
     )))
   `((name . "CLOSURE")
     (steps . (
       (capture-free-vars)
       (alloc-closure)
       (write-reg closure)
     )))
   `((name . "CLOSURE_GET")
     (steps . (
       (stack-load v1 closure)
       (stack-load v2 fixnum)
       (closure-get)
       (write-reg slot)
     )))
   `((name . "CONST")
     (steps . (
       (const-load)
       (write-reg constant)
     )))
   `((name . "DEFINE")
     (steps . (
       (const-load)
       (stack-load reg any)
       (define-symbol)
       (write-reg symbol)
     )))
   `((name . "EQ")
     (steps . (
       (stack-load v1 any)
       (stack-load v2 any)
       (eq-compare)
       (write-reg boolean)
     )))
   `((name . "EXACT")
     (steps . (
       (stack-load v1 flonum)
       (convert-to-exact)
       (write-reg fixnum)
     )))
   `((name . "FCALL")
     (steps . (
       (prepare-fcall)
       (call-ffi)
       (write-reg result)
     )))
   `((name . "FUNC")
     (steps . (
       (prepare-call func)
       (check-arity exact)
       (call-dispatch closure)
     )))
   `((name . "FUNCV")
     (steps . (
       (prepare-call funcv)
       (check-arity variadic)
       (build-rest-args)
       (call-dispatch closure)
     )))
   `((name . "ADD")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (arith-overflow add)
       (write-reg fixnum-or-false)
     )))
   `((name . "DIV")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (arith-div)
       (write-reg fixnum)
     )))
   `((name . "EQ")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (compare-overflow eq)
       (write-reg boolean)
     )))
   `((name . "LT")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (compare-overflow lt)
       (write-reg boolean)
     )))
   `((name . "LTE")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (compare-overflow lte)
       (write-reg boolean)
     )))
   `((name . "GT")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (compare-overflow lt)
       (write-reg boolean)
     )))
   `((name . "GTE")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (compare-overflow lte)
       (write-reg boolean)
     )))
   `((name . "MOD")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (arith-mod)
       (write-reg fixnum)
     )))
   `((name . "MUL")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (arith-overflow mul)
       (write-reg fixnum-or-false)
     )))
   `((name . "SUB")
     (steps . (
       (stack-load v1 fixnum)
       (stack-load v2 fixnum)
       (arith-overflow sub)
       (write-reg fixnum-or-false)
     )))
   `((name . "GUARD")
     (steps . (
       (stack-load v1 any)
       (stack-load v2 tag)
       (guard-type)
       (write-reg boolean)
     )))
   `((name . "HALT")
     (steps . (
       (halt)
     )))
   `((name . "ICFUNC")
     (steps . (
       (prepare-call icfunc)
       (check-arity conditional)
       (call-dispatch inline)
     )))
   `((name . "ICFUNCV")
     (steps . (
       (prepare-call icfuncv)
       (check-arity conditional-variadic)
       (build-rest-args)
       (call-dispatch inline)
     )))
   `((name . "IF")
     (steps . (
       (stack-load reg truthy)
       (branch-if-false)
       (adjust-pc-for-branch)
     )))
   `((name . "IFUNC")
     (steps . (
       (prepare-call ifunc)
       (check-arity exact)
       (call-dispatch inline)
     )))
   `((name . "IFUNCV")
     (steps . (
       (prepare-call ifuncv)
       (check-arity variadic)
       (build-rest-args)
       (call-dispatch inline)
     )))
   `((name . "ILOOP")
     (steps . (
       (loop-noop)
     )))
   `((name . "INEXACT")
     (steps . (
       (stack-load v1 fixnum)
       (convert-to-inexact)
       (write-reg flonum)
     )))
   `((name . "INTEGER_CHAR")
     (steps . (
       (stack-load v1 fixnum)
       (int->char)
       (write-reg char)
     )))
   `((name . "JCFUNC")
     (steps . (
       (prepare-call jcf)
       (check-arity exact)
       (jit-call-dispatch cfunc)
     )))
   `((name . "JCFUNCV")
     (steps . (
       (prepare-call jcfv)
       (check-arity variadic)
       (build-rest-args)
       (jit-call-dispatch cfunc)
     )))
   `((name . "JFUNC")
     (steps . (
       (prepare-call jfunc)
       (check-arity exact)
       (jit-call-dispatch closure)
     )))
   `((name . "JFUNCV")
     (steps . (
       (prepare-call jfuncv)
       (check-arity variadic)
       (build-rest-args)
       (jit-call-dispatch closure)
     )))
   `((name . "JLOOP")
     (steps . (
       (record-loop-entry)
       (jit-dispatch-loop)
     )))
   `((name . "JMP")
     (steps . (
       (jump-relative)
     )))
   `((name . "LCALL")
     (steps . (
       (prepare-call local)
       (check-arity exact)
       (call-dispatch local)
     )))
   `((name . "LCALLT")
     (steps . (
       (prepare-call local-tail)
       (check-arity exact)
       (tail-dispatch local)
     )))
   `((name . "LJMP")
     (steps . (
       (load-loop-target)
       (move-frame-for-loop)
       (jump-loop)
     )))
   `((name . "LOAD")
     (steps . (
       (stack-load v1 aggregate)
       (stack-load v2 fixnum)
       (load-field word)
       (write-reg value)
     )))
   `((name . "LOAD_CHAR")
     (steps . (
       (stack-load v1 string)
       (stack-load v2 fixnum)
       (load-field char)
       (write-reg char)
     )))
   `((name . "LOOKUP")
     (steps . (
       (const-load)
       (ensure-type symbol)
       (lookup-symbol)
       (write-reg value)
     )))
   `((name . "LOOP")
     (steps . (
       (hotmap-check)
       (maybe-start-trace)
       (advance-pc)
     )))
   `((name . "MOV")
     (steps . (
       (mov)
       (write-reg value)
     )))
   `((name . "RET")
     (steps . (
       (return-frame)
     )))
   `((name . "STORE")
     (steps . (
       (stack-load reg aggregate)
       (stack-load v1 any)
       (stack-load v2 fixnum)
       (store-field word)
     )))
   `((name . "STORE_CHAR")
     (steps . (
       (stack-load reg string)
       (stack-load v1 char)
       (stack-load v2 fixnum)
       (store-field char)
     )))
   `((name . "WRITE")
     (steps . (
       (stack-load v1 any)
       (stack-load v2 port)
       (io-write)
       (write-reg undefined)
     )))
  ))

(define (main)
  (display "vmgen step generators not implemented yet\n"))

(main)
