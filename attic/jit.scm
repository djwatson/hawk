(include "parcopy.scm")
(define (jit-emit-world graph)
  ;; TODO better way to do this?  size checking?
  ;; TODO merge code/stubs,  and jit-label, all in some sort of buffer output.
  ;; cranelift 4-part blog (regalloc2) has lots of info.
  (define code (make-code (* 2 4096)))
  (define stubs (make-code-offset code 4096))
  (define sched (make-hamt))
  (define dead-at-op (make-hamt))
  (define reg-hints (make-hamt))
  ;; TODO it's weird to include this inline in the emitter, no longer necessary?
  ;; It implicitly binds 'code' in a few functions.
  (include "ctx.scm")
  (define label-versions (make-hamt))
  (define label-version-cnt (make-hamt))
  ;; This is mostly so we don't have to scan jitted stubs for GC.  It's just a number,
  ;; actual data held in ctx-ids global, which GC already scans.
  (define ctx-ids (make-hamt))
  (define (jit-emit-function arg-types label)
    (define ctx (make-jit-ctx))
    (define params (filter
                    (lambda (x) 
                      (define op (hamt/get graph x '()))
                      (not (param-cont op)))
                    (get-params graph label)))
    (set-ctx-types! ctx arg-types)
    (display "emit function ")
    (display label)
    (display " arg types ") (display arg-types)
    (newline)
    (for
      (param reg)
      (params arg-regs)
      (display "set param ")
      (display (param-name (hamt/get graph param #f)))
      (display " to ")
      (display reg)
      (newline)
      (ctx-add-loc ctx param reg)
      (ctx-remove-free ctx reg))
    (jit-emit-label ctx label))

  ;; TODO this could be merged with gen-stub,
  ;; and capture all the context necessary instead
  ;; would be more readable.
  (define (gen-stub-cb ctx-id)
    (define stub-ctx (hamt/find ctx-ids ctx-id))
    (define stub-label-ret (first stub-ctx))
    (define ctx (second stub-ctx))
    (define branch-label (third stub-ctx))
    (define stub-label (cadddr stub-ctx))
    (define original-branch-loc (cadddr (cdr stub-ctx)))
    (define updated (cadddr (cddr stub-ctx)))
    (define stub-other-label (cadddr (cdddr stub-ctx)))
    ;; Either
    ;; continue, overwritting the last jump (fallthrough) jcc, jmp -> jcc, ...
    ;; swap branches, continue writing code. jcc, jmp -> 'jcc, ...
    ;; or just update the jump, there is already valid code., jcc, jmp, ... -> jcc, 'jmp, ..., ...
    (cond
      ((and
          (not (car updated))
          (<=
            (- (get-code-offset code) original-branch-loc)
            5))
        (display "Merging the branch to continue\n")
        (set-code-offset! code (- (get-code-offset code) 5)))
      ((and
          (not (car updated))
          (<=
            (- (get-code-offset code) original-branch-loc)
            11))
        (display "Swapping branches\n")
        ;; Swap the jcc.
        (set-code-offset! code (- (get-code-offset code) 10))
        (set-code-byte! code (bitwise-xor 1 (get-code-byte code)))
        ;; Update old call location to new, so other branch will
        ;; update the correct location.
        (label-update-caller
          stub-other-label
          (+ 5 (get-code-offset code))
          (get-code-offset code))
        (emit-label-offset code stub-other-label))
      (else (change-label code stub-label)))
    ;; Change branch to point to new code instead.
    (display "Got a call! updated:")
    (display (car updated))
    (newline)
    (set-car! updated #t)
    (display ctx-id)
    (newline)
    (add-label code stub-label-ret)
    (jit-emit-label ctx branch-label)
    (display "Return from stub")
    (newline)
    (dump-asm)
    ;; TODO reclaim stub space?
    (hamt/delete! ctx-ids ctx-id))

  (define (jit-emit-label ctx label)
    ;; TODO label needs a version also.
    (define version (cons label (ctx-types ctx)))
    ;; TODO merge ctx (create movs and shit) if already found.
    (if (not (hamt/get label-versions version #f)) 
	(let ((cnt (+ 1 (hamt/get label-version-cnt label 0))))
	  (display "Adding label ") (display label) (display " number ") (display cnt)
	  (display " ctx ") (display (ctx-types ctx)) (newline)
	  (hamt/insert! label-version-cnt label cnt)
        (hamt/insert! label-versions version ctx)
        (jit-emit-label-body ctx label))
      (emit-jmp32 code (ctx-versioned-label ctx label))))

  (define (jit-emit-label-body ctx label)
    ;; TODO  - branch fusion should operate as a separate backwards pass
    ;; of instruction scheduling.
    (define can-fuse-branch #f)
    (display "emit label ")
    (display label)
    (newline)
    (add-label code (ctx-versioned-label ctx label))
    ;; TODO: phis for params?  MOV? merging of contexts.
    ;; Check for branch fusing.
    (let ((last (last-or-null (hamt/get sched label '()))))
      (if (number? last) 
        (let ((l (hamt/get graph last '()))
              (cur (hamt/get graph label #f)))
          (if (and
                (builtin-call? l)
                (eq? 'fx< (builtin-builtin l))
                (branch? (label-next cur))
                (member last (hamt/get dead-at-op label '()))) 
            (set! can-fuse-branch #t)))))
    (display "Can fuse:")
    (display can-fuse-branch)
    ;(set! can-fuse-branch #f)
    (newline)
    (if can-fuse-branch 
      (let* ((ops (hamt/get sched label '()))
             (rev (reverse ops))
             (fused (car rev))
             (rest (reverse (cdr rev))))
        (for op rest
          (jit-emit-op op ctx #f))
        (jit-emit-op fused ctx #t)
        (jit-emit-next
          ctx
          label
          (label-next (hamt/get graph label #f))
          (builtin-builtin (hamt/get graph fused #f))))
      (begin
        (for op (hamt/get sched label '())
          (jit-emit-op op ctx #f))
        (jit-emit-next
          ctx
          label
          (label-next (hamt/get graph label #f))
          #f))))

  (define (jit-emit-next ctx label n fused)
    (display "Emit next:")
    (display-op n)
    (newline)
    (cond
      ((call? n) (jit-emit-call ctx label n))
      ((branch? n)
        (jit-emit-branch ctx label n fused))
      (else (error "Unknown emit-next:" label))))

  (define (jit-free-dead ctx op)
    (for op (hamt/get dead-at-op op '())
      (ctx-free-loc ctx op)))

  (define (jit-remove-dead ctx op)
    (for op (hamt/get dead-at-op op '())
	 (ctx-delete-loc ctx op)))

  (define unique-stub-id
    (let ((id 0))
      (lambda ()
	(define ret id)
	(set! id (+ 1 id))
	ret)))

  (define (jit-emit-stub ctx label other-label updated)
    ;; Alloc stub
    (define stub-label (cons (ctx-versioned-label ctx label) 'stub))
    (define stub-other-label (cons
                              (ctx-versioned-label ctx other-label)
                              'stub))
    (define stub-label-ret (cons
                            (ctx-versioned-label ctx label)
                            'stub-ret))
    (define id (unique-stub-id))
    (hamt/insert!
      ctx-ids
      id
      (list
        stub-label-ret
        ctx
        label
        stub-label
        (get-code-offset code)
        updated
        stub-other-label))
    ;; TODO check stack even
    (add-label stubs stub-label)
    (ctx-push-all-stub ctx stubs)
    (emit-mov64 stubs rax stub-address)
    (emit-mov64 stubs rdi id)
    (emit-call-indirect stubs rax)
    (ctx-pop-all-stub ctx stubs)
    ;; We have now returned, jmp.
    (emit-jmp32 stubs stub-label-ret)
    stub-label)

  (define (jit-emit-branch ctx label n fused)
    ;; TODO also remove dead at next block (label)
    ;; TODO check already generated
    (let ((reg (ctx-get-reg ctx (branch-cond n)))
          (updated (list #f)))
      (jit-free-dead ctx label)
      (jit-remove-dead ctx label)
      ;; WARNING: emit-stub currently uses the offset. 
      (if (not fused) 
        (emit-test-reg-reg code reg reg))
      (let ((stub1
              (jit-emit-stub
                ctx
                (branch-l1 n)
                (branch-l2 n)
                updated)))
        (if fused 
          (emit-jcc32 code 'jl stub1)
          (emit-jcc32 code 'jnz stub1))
        (let ((stub2
                (jit-emit-stub
                  (duplicate-ctx ctx)
                  (branch-l2 n)
                  (branch-l1 n)
                  updated)))
          (emit-jmp32 code stub2)))))

  (define (jit-emit-call ctx label n)
    (define (get-continuation graph params args)
      (if (param-cont (hamt/get graph (car params) #f)) 
        (car args)
        (get-continuation
          graph
          (cdr params)
          (cdr args))))

    (let* ((target-label (car (call-args n)))
           (target (hamt/get graph target-label '())))
      (cond
        ((and (param? target) (param-cont target))
          (display "EMIT RET\n")
          (ctx-mov-op ctx (cadr (call-args n)) rax)
	  ;; Check if it needs tagging
	  (when (assoc (cadr (call-args n)) (ctx-types ctx))
	    (emit-shl-reg-imm8 code rax 3))
          ;(emit-pop code rbp)
          (ctx-pop-stack code ctx)
          (emit-ret code))
        ((and
            (label? target)
            (label-function-like? graph target-label))
          (let ((cont
                  (get-continuation
                    graph
                    (get-params graph (car (call-args n)))
                    (cdr (call-args n)))))
	    (define (find-arg-types)
	      (define types '())
	      (for
	       (param arg)
	       ((get-params graph target-label) (cdr (call-args n)))
	       (when (assoc arg (ctx-types ctx))
		 (push! types (cons param (cdr (assoc arg (ctx-types ctx)))))))
	      types)
	    (define arg-types (find-arg-types))
            (define (apply-args)
              (define serialized '())
              (define constants '())
              (for
                (param reg)
                ((cdr (call-args n)) arg-regs)
                (if (not (eq? cont param)) 
                  (if (ctx-is-constant? ctx param) 
                    (push! constants (list param reg))
                    (push! serialized (list (ctx-get-reg ctx param) reg)))))
              (for constant constants
                (ctx-mov-op
                  ctx
                  (first constant)
                  (second constant)))
              (for move (serialize-parallel-copy serialized)
                (case (first move)
                  ((mov)
                    (emit-mov-reg-reg
                      code
                      (second move)
                      (third move)))
                  ((xchg)
                    (emit-xchg-reg-reg
                      code
                      (second move)
                      (third move)))
                  (else (error "Unknown serialize pcopy:" move)))))

            (if (call-is-tail n) 
              (begin
                #;(emit-pop code rbp)
                (jit-free-dead ctx label)
                (apply-args)
                (jit-remove-dead ctx label)
                (ctx-pop-stack code ctx)
                ;; TODO emit versioned stubs?
		(let ((vlabel (cons target-label arg-types)))
		  (if (hamt/get label-versions vlabel #f)
                      (emit-jmp32 code vlabel)
		      (jit-emit-function arg-types  target-label) ;; TODO vlabel
		      )))
              (begin
                ;; non-tail calls
                ;; TODO can remove dead at op I think?
                (ctx-push-all ctx code dead-at-op label)
                (jit-free-dead ctx label)
                (apply-args)
                (jit-remove-dead ctx label)
                (display "EMITTING CALL TO CTX: ")
                (display arg-types)
                (newline)
                (emit-call32 code (cons target-label arg-types))
                (let ((reg rax #;(ctx-get-free-reg-hint ctx (hamt/get reg-hints label #f))))
                  (if (not (eq? rax reg)) 
                    (emit-mov-reg-reg code rax reg))
                  (ctx-pop-all ctx code)
                  (ctx-add-loc
                    ctx
                    (car (get-params graph cont))
                    reg))
                (jit-emit-label ctx cont)
		(if (not (hamt/get label-versions (cons target-label arg-types) #f))
		    (jit-emit-function arg-types  target-label))) ;; TODO vlabel
		)))
        ((label? target)
          (display "EMIT LABEL JMP\n")
          (for
            (param arg)
            ((get-params graph target-label)
              (cdr (call-args n)))
            (ctx-add-loc ctx param (hamt/find (jit-locs ctx) arg)))
          (jit-free-dead ctx label)
          (jit-remove-dead ctx label)
          (jit-emit-label ctx target-label))
        (else (error "Unknown jit-emit-call")))))

  (define (jit-emit-constant op ctx)
    (let ((c (hamt/get graph op #f)))
      (cond
        ((number? (constant-c c))
          (ctx-add-constant ctx op c))
        (else (error "Unknown jit constant:" (constant-c c))))))

  (define (jit-emit-op op ctx fused)
    (display "Emit op")
    (display op)
    (newline)
    ;;TODO can't free dead for fx< because of xor
    (let ((r (hamt/get graph op #f)))
      (cond
        ((constant? r) (jit-emit-constant op ctx))
        ((builtin-call? r)
          (case (builtin-builtin r)
            ('fx+
              (if (member
                    (second (builtin-call-args r))
                    (hamt/get dead-at-op op '())) 
                (ctx-free-loc ctx (second (builtin-call-args r))))
              (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
                (if (ctx-is-constant? ctx (car (builtin-call-args r))) 
                  (begin
                    (ctx-mov-op
                      ctx
                      (cadr (builtin-call-args r))
                      reg)
                    (emit-add-reg-imm32 code reg (ctx-get-constant ctx (car (builtin-call-args r)))))
                  (begin
                    (ctx-mov-op
                      ctx
                      (cadr (builtin-call-args r))
                      reg)
                    (emit-add-reg-reg
                      code
                      (ctx-get-reg ctx (car (builtin-call-args r)))
                      reg)))
                (ctx-add-loc ctx op reg))
              (jit-free-dead ctx op))
            ('fx-
              (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
                (if (ctx-is-constant? ctx (cadr (builtin-call-args r))) 
                  (begin
                    (ctx-mov-op
                      ctx
                      (car (builtin-call-args r))
                      reg)
                    (emit-sub-reg-imm32 code reg (ctx-get-constant ctx (cadr (builtin-call-args r)))))
                  (begin
                    (ctx-mov-op
                      ctx
                      (car (builtin-call-args r))
                      reg)
                    (emit-reg-reg
                      code
                      #x29
                      (ctx-get-reg ctx (cadr (builtin-call-args r)))
                      reg)))
                (ctx-add-loc ctx op reg))
              (jit-free-dead ctx op)
              ;; TODO only can't use the *other* reg
              )
            ('fx<
              (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
                (if (not fused) 
                  (emit-xor-reg-reg code reg reg))
                (if (ctx-is-constant? ctx (cadr (builtin-call-args r))) 
                  (emit-cmp-reg-imm32
                    code
                    (ctx-get-reg ctx (car (builtin-call-args r)))
                    (ctx-get-constant ctx (cadr (builtin-call-args r))))
                  (emit-cmp-reg-reg
                    code
                    (ctx-get-reg ctx (car (builtin-call-args r)))
                    (ctx-get-reg ctx (cadr (builtin-call-args r)))))
                (if (not fused) 
                  (emit-set-lt-reg code reg))
                (jit-free-dead ctx op)
                (ctx-add-loc ctx op reg)))
            ('untag
	     ;; TODO unused reg here and tag
	     (display "FREE REG ") (display (free-regs ctx)) (newline)
             (jit-free-dead ctx op)
	     (display "AFREE REG ") (display (free-regs ctx)) (newline)
	     (let  ((untagged (assoc (car (builtin-call-args r)) (ctx-types ctx))))
	       (if (and untagged (ctx-is-constant? ctx (car (builtin-call-args r)))
			)
		   (ctx-copy-loc ctx (car (builtin-call-args r)) op)
		   
		   (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
		     (display "CHECKING REG ") (display untagged) (display " new reg ") (display reg) (newline)
		     (if untagged
			 (begin
			   (ctx-mov-op ctx (car (builtin-call-args r)) reg)
			   (ctx-add-loc ctx op reg))
			 (begin
			   (ctx-mov-op
			    ctx
			    (car (builtin-call-args r))
			    reg)
			   (emit-ashr-reg-imm8 code reg 3)
			   (ctx-add-loc ctx op reg)))))))
            ('tag
              (jit-free-dead ctx op)
              (ctx-add-type ctx op 'fixnum)
              (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
		(if (ctx-is-constant? ctx (car (builtin-call-args r)))
		    (ctx-copy-loc ctx (car (builtin-call-args r)) op)
		    (begin
		      (ctx-mov-op ctx (car (builtin-call-args r)) reg)
		      (ctx-add-loc ctx op reg))))
	      (display (hamt-for k v (jit-locs ctx) (display k) (display " ") (display v) (newline)))
              ;; (let ((reg (ctx-get-free-reg-hint ctx (hamt/get reg-hints op #f))))
              ;;   (begin
              ;;     (ctx-mov-op
              ;;       ctx
              ;;       (car (builtin-call-args r))
              ;;       reg)
              ;;     (emit-shl-reg-imm8 code reg 3))
              ;;   (ctx-add-loc ctx op reg))
	      )
            (else
              (display-op r)
              (error "Unknown builtin:" r))))
        (else (error "Uknown jit-emit-op:" (hamt/get graph op #f)))))
    (jit-remove-dead ctx op))

  (define (dump-asm)
    (display "CODE:")
    (newline)
    (disassemble
      code
      0
      (get-code-offset code)
      disassemble_address)
    ;; (display "STUBS:")
    ;; (newline)
    ;; (disassemble
    ;;   stubs
    ;;   4096
    ;;   (- (get-code-offset stubs) 4096)
    ;;   disassemble_address)
    )

  (scope-for entry graph
    (display "Emitting ")
    (display entry)
    (newline)
    (let* ((scope (scope graph entry))
           (cfg (cfg graph scope))
           (rpo (cfg-rpo cfg entry))
           (domtree (domtree rpo cfg))
           (cfg-preds (cfg-preds cfg))
           (uses (graph-uses graph))
           (looptree (looptree rpo cfg)))
      (hamt-merge! sched (schedule domtree rpo graph uses domtree looptree))
      (hamt-merge! dead-at-op (analyze-live graph rpo sched cfg-preds))
      (hamt-merge! reg-hints (generate-reg-hints graph rpo sched cfg-preds dead-at-op))))
  (jit-emit-function '()  0)
  (dump-asm)
  (set-stub-cb gen-stub-cb)
  (display (run-code code 0)))

