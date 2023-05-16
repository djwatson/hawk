;;; CAT -- One of the Kernighan and Van Wyk benchmarks.

(define inport #f)
(define outport #f)

(define (catport port)
  (let ((x (read-char port)))
    (if (eof-object? x)
        (close-output-port outport)
        (begin
          (write-char x outport)
          (catport port)))))

(define (go)
  (set! inport (open-input-file "./test/bench/bib"))
  (set! outport (open-output-file "./test/bench/foo"))
  (catport inport)
  (close-input-port inport))

(go)
(println "END")

;END
