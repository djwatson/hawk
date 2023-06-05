(define-library
  (jit-chicken)
  (import
    (r7rs)
    (scheme write)
    (chicken foreign)
    (chicken memory))
  (export
    make-code
    make-code-offset
    run-code
    set-code-byte!
    get-code-byte
    disassemble
    stub-address
    get-code-offset
    set-code-offset!
    set-stub-cb)
  (begin
    (define-record-type jit-code (make-jit-code code offset) jit-code?
      (code get-code-pointer set-code-pointer!)
      (offset get-code-offset set-code-offset!))
    ;; The entirety of the necessary external interface.
    ;; Note that we rely on overcommit for mmap - so we can't move-memory
    ;; in to a string using the native chicken mmap interface.
    (foreign-declare "#include <sys/mman.h>")
    (foreign-declare "#include <capstone/capstone.h>")
    (define (make-code sz)
      (make-jit-code (make-code-foreign sz) 0))

    (define (make-code-offset code offset)
      (make-jit-code (get-code-pointer code) offset))

    (define make-code-foreign (foreign-lambda*
                               (c-pointer unsigned-byte)
                               ((int sz))
                               "C_return(mmap(NULL, sz, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));"))
    (define (run-code code offset)
      (run-code-foreign
        (get-code-pointer code)
        offset))

    (define run-code-foreign (foreign-safe-lambda*
                              unsigned-long
                              (((c-pointer unsigned-byte) code)
                                (unsigned-long offset))
                              "unsigned long(*fun_ptr)() = (unsigned long(*)())(code + offset);"
                              "C_return(fun_ptr());"))
    ;; TODO assert size check
    (define (set-code-byte! c byte)
      (pointer-u8-set!
        (pointer+
          (get-code-pointer c)
          (get-code-offset c))
        byte)
      (set-code-offset! c (+ 1 (get-code-offset c))))

    (define (get-code-byte c)
      (pointer-u8-ref
        (pointer+
          (get-code-pointer c)
          (get-code-offset c))))

    ;; Callback for the stub.
    (define stub-cb 1)
    (define (set-stub-cb cb)
      (set! stub-cb cb))

    (define-external
      (gen_stub (unsigned-long ctx-id))
      unsigned-long
      (stub-cb ctx-id)
      0)
    (define stub-address (pointer->address (location gen_stub)))
    ;; Additional capstone disassembler.
    (define (disassemble code start sz cb)
      (disassemble-foreign
        (get-code-pointer code)
        (pointer+ (get-code-pointer code) start)
        sz
        cb))

    (define disassemble-foreign (foreign-safe-lambda*
                                 unsigned-int
                                 (((c-pointer unsigned-byte) code_start)
                                   ((c-pointer unsigned-byte) code)
                                   (unsigned-long sz)
                                   (scheme-object cb))
                                 "  
        csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		C_return(-1);
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	count = cs_disasm(handle, code, sz, (uint64_t)code, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
                        C_save(C_SCHEME_FALSE);
                        C_save(C_fix(insn[j].address - (unsigned long int)code_start));
                        C_callback(cb, 2);
			printf(\"0x%\"PRIx64\":\\t%s\\t\\t%s\", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
                        if (cs_insn_group(handle, &insn[j], X86_GRP_JUMP) ||
                            cs_insn_group(handle, &insn[j], X86_GRP_CALL)) {
		            for (int i = 0; i < insn->detail->x86.op_count; i++) {
			         if (insn[j].detail->x86.operands[i].type == X86_OP_IMM) {
                                      C_save(C_SCHEME_TRUE);
                                      C_save(C_fix(insn[j].detail->x86.operands[i].imm - (unsigned long int)code_start));
                                      C_callback(cb, 2);
			         }
		            }
	                 }
                        printf(\"\\n\");
		}

		cs_free(insn, count);
	} else
		printf(\"ERROR: Failed to disassemble given code!\\n\");

	cs_close(&handle);

        C_return(0);
"))))
