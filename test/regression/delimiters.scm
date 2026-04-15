(import (scheme read) (scheme base) (scheme write))

;; ' is not allowed in an un-escaped symbol, but it is not a delimiter.
;; Many schemes don't check for missing delimiter, but will return 'a.
(guard
    (obj ((read-error? obj) #t))
  (let ((val (read (open-input-string "'a'b"))))
    (write val)
    (newline)
    (if (equal? ''a val)
	(error "Missing delimiter")
      (error "Malformed read"))))
