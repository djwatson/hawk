(import (scheme base) (scheme write))

(define pass-count 0)
(define fail-count 0)

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (equal? result expected)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected ")
             (write expected)
             (display " got ")
             (write result)
             (newline)))))))

;; string->utf8 basic
(check (string->utf8 "") #u8())
(check (string->utf8 "ABC") #u8(#x41 #x42 #x43))
(check (string->utf8 "abc") #u8(#x61 #x62 #x63))

;; string->utf8 with start/end
(check (string->utf8 "ABC" 1) #u8(#x42 #x43))
(check (string->utf8 "ABC" 1 2) #u8(#x42))
(check (string->utf8 "ABC" 0 0) #u8())

;; utf8->string basic
(check (utf8->string #u8()) "")
(check (utf8->string #u8(#x41 #x42 #x43)) "ABC")
(check (utf8->string #u8(#x61 #x62 #x63)) "abc")

;; utf8->string with start/end
(check (utf8->string #u8(#x41 #x42 #x43) 1) "BC")
(check (utf8->string #u8(#x41 #x42 #x43) 1 2) "B")
(check (utf8->string #u8(#x41 #x42 #x43) 0 0) "")

;; Round-trip ASCII
(let ((s "Hello, World!"))
  (check (utf8->string (string->utf8 s)) s))

;; Round-trip empty
(check (utf8->string (string->utf8 "")) "")

;; Round-trip with start/end
(let ((s "ABCDEF"))
  (check (utf8->string (string->utf8 s 2 4) 0) "CD"))

;; 2-byte UTF-8 (U+0080 to U+07FF)
(let ((bv (string->utf8 (string (integer->char #xa3)))))
  (check bv #u8(#xC2 #xA3)))
(check (utf8->string #u8(#xC2 #xA3))
       (string (integer->char #xa3)))

;; 3-byte UTF-8 (U+0800 to U+FFFF)
(let ((bv (string->utf8 (string (integer->char #x20ac)))))
  (check bv #u8(#xE2 #x82 #xAC)))
(check (utf8->string #u8(#xE2 #x82 #xAC))
       (string (integer->char #x20ac)))

;; Mix of ASCII and multi-byte
(let ((bv (string->utf8 (string #\A (integer->char #xa3) (integer->char #x20ac)))))
  (check (bytevector-length bv) 6)
  (check (utf8->string bv)
         (string #\A (integer->char #xa3) (integer->char #x20ac))))

;; string->utf8 returns bytevector
(check (bytevector? (string->utf8 "test")) #t)

;; utf8->string returns string
(check (string? (utf8->string #u8(#x41))) #t)

;; Boundary: last 1-byte (U+007F)
(check (string->utf8 (string (integer->char #x7f))) #u8(#x7f))

;; Unicode UTF-8 boundaries.
(check (string->utf8 (string (integer->char #x80))) #u8(#xc2 #x80))
(check (string->utf8 (string (integer->char #x7ff))) #u8(#xdf #xbf))
(check (string->utf8 (string (integer->char #x800))) #u8(#xe0 #xa0 #x80))

;; Result
(newline)
(display "UTF-8: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
