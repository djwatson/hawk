(import (scheme base) (scheme file) (scheme write))

(define-syntax test-ok
   (syntax-rules ()
     ((_ a) (test-ok 'a a))
     ((_ name a)
      (let ((err (guard (cxp (#t #t)) a #f)))
        (when err (display "FAIL:") (display name) (newline) (display 'a) (newline))))))

(define-syntax test-error
   (syntax-rules ()
     ((_ a)
      (let ((err (guard (cxp (#t #t)) a #f)))
        (unless err (display "FAIL:") (display 'a) (newline))))))

(call-with-port (open-output-file "tmps123")
                (lambda (port) (display "HI\n" port)))
(call-with-output-file "tmp"
  (lambda (out-port)
    (test-ok (output-port? out-port))
    (test-ok (not (input-port? out-port)))
    (test-error (peek-char out-port))
    (test-ok (write-char #\C out-port))))
(call-with-input-file "tmp"
  (lambda (in-port)
    (test-ok (input-port? in-port))
    (test-error (peek-u8 in-port))
    (test-ok (peek-char in-port))
    (test-ok (not (output-port? in-port)))
    (test-error (write-char #\( in-port))))
