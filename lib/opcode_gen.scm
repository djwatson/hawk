(include "util.scm")

(define (d2format port format-string . objects)
  (define (format-error message)
    (error message format-string))
  (let loop ((format-list (string->list format-string))
             (objects objects))
    (cond ((null? format-list) #f) ;; done
          ((char=? (car format-list) #\~)
           (if (null? (cdr format-list))
               (format-error "Incomplete escape sequence")
               (case (cadr format-list)
                 ((#\a)
                  (if (null? objects)
                      (format-error "No value for escape sequence")
                      (begin
                        (display (car objects) port)
                        (loop (cddr format-list) (cdr objects)))))
                 ((#\s)
                  (if (null? objects)
                      (format-error "No value for escape sequence")
                      (begin
                        (write (car objects) port)
                        (loop (cddr format-list) (cdr objects)))))
                 ((#\%)
                  (newline)
                  (loop (cddr format-list) objects))
                 ((#\~)
                  (write-char #\~ port)
                  (loop (cddr format-list) objects))
                 (else
                  (format-error "Unrecognized escape sequence")))))
          (else (write-char (car format-list) port)
                (loop (cdr format-list) objects)))))

(define opcodes '())

(define (read-line . port)
  (define (eat p c)
    (if (and (not (eof-object? (peek-char p)))
             (char=? (peek-char p) c))
        (read-char p)))
  (let ((p (if (null? port) (current-input-port) (car port))))
    (let loop ((c (read-char p)) (line '()))
      (cond ((eof-object? c) (if (null? line) c (list->string (reverse line))))
            ((char=? #\newline c) (eat p #\return) (list->string (reverse line)))
            ((char=? #\return c) (eat p #\newline) (list->string (reverse line)))
            (else (loop (read-char p) (cons c line)))))))

(define (string-split str chrs)
  (define l (string->list str))
  (let loop ((l l) (cur '()))
    (if (pair? l)
	(if (memq (car l) chrs)
	    (cons (list->string (reverse cur)) (loop (cdr l) '()))
	    (loop (cdr l) (cons (car l) cur)))
	(list (list->string (reverse cur))))))

(define (strip-quotes str)
  (if (eq? #\" (string-ref str 0))
      (substring str 1 (- (string-length str) 1))
      str))

(define (find-lib-funcs file)
  (define p (open-input-file file))
  (let loop ()
    (define line (read-line p))
    (if (not (eof-object? line))
	(begin
	  (if (and (>= (string-length line) 7)
		   (equal? "LIBRARY" (substring line 0 7)))
	      (let ((new-code (string->symbol (strip-quotes (second (string-split line '(#\( #\) #\,)))))))
		(set! opcodes	(append opcodes (list (list new-code))))))
	  (loop))))
  (close-input-port p))

(find-lib-funcs "../src/vm.c")
(dformat "There are ~a opcodes\n" (length opcodes))
;(pretty-print opcodes)

(define (c-var-name str)
  (list->string (filter-map (lambda (chr)
			      (case chr
				((#\-) #\_)
				((#\! #\> #\?) #f)
				(else chr)))
		(string->list str))))

(set! opcodes (map (lambda (code num)
		     (append code (list num (c-var-name (symbol->string (car code))))))
		   opcodes
		   (iota (length opcodes))))


(define opcode-cpp (open-output-file "../src/opcodes.c"))
(display "const char* ins_names[] = {\n" opcode-cpp)
(for-each (lambda (op)
	    (d2format opcode-cpp "  \"~a\",\n" (symbol->string (car op)))) opcodes)
(display "};\n" opcode-cpp)
(close-output-port opcode-cpp)

(define opcode-h (open-output-file "../src/opcodes.h"))
(display "#pragma once\n\n" opcode-h)
(display "extern const char* ins_names[];\n" opcode-h)
(display "enum {\n" opcode-h)
(for-each (lambda (op)
	    (d2format opcode-h "  ~a,\n" (caddr op))) opcodes)
(display "  INS_MAX\n" opcode-h)
(display "};\n" opcode-h)
(close-output-port opcode-h)

(define op-table-h (open-output-file "../src/opcodes-table.h"))
(display "#ifdef PROFILER\n" op-table-h)
(for-each (lambda (op)
	    (d2format op-table-h "void INS_PROFILE_~a(unsigned char ra, unsigned instr, unsigned *pc, long *frame, void **op_table_arg, long argcnt) {\n" (caddr op))
	    (display "profile_set_pc(pc);\n" op-table-h)
	    (d2format op-table-h "MUSTTAIL return INS_~a(ra, instr, pc, frame, op_table_arg, argcnt);\n" (caddr op))
	    (display "}\n" op-table-h)
	    )
	  opcodes)
(display "#endif\n" op-table-h)
(d2format op-table-h "static void opcode_table_init() {")
(for-each (lambda (op)
	    (d2format op-table-h "  l_op_table[~a] = INS_~a;\n" (caddr op) (caddr op))
	    (display "#ifdef PROFILER\n" op-table-h)
	    (d2format op-table-h "  l_op_table_profile[~a] = INS_PROFILE_~a;\n" (caddr op) (caddr op))
	    (display "#endif\n" op-table-h)) opcodes)
(d2format op-table-h  "}")

(close-output-port op-table-h)

(define opcode-scm (open-output-file "opcodes.scm"))
(display "(define opcodes '(\n" opcode-scm)
(for-each (lambda (op)
	    (d2format opcode-scm "  (~a ~a)\n" (symbol->string (car op)) (cadr op)))
	  opcodes)
(display "))\n" opcode-scm)
(close-output-port opcode-scm)
