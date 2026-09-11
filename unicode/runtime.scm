;; Sorted records: ranges (start end), maps (start end stride delta),
;; and full-case exceptions (codepoint string).
(define (unicode-find table n width)
  (let loop ((lo 0) (hi (- (quotient (vector-length table) width) 1)))
    (if (> lo hi)
        #f
        (let* ((mid (quotient (+ lo hi) 2)) (pos (* mid width))
               (start (vector-ref table pos)))
          (cond
            ((< n start) (loop lo (- mid 1)))
            ((> n (if (= width 2) start (vector-ref table (+ pos 1))))
             (loop (+ mid 1) hi))
            (else pos))))))

(define (unicode-property? table n)
  (let loop ((lo 0) (hi (- (quotient (vector-length table) 2) 1)))
    (if (> lo hi)
        #f
        (let* ((mid (quotient (+ lo hi) 2)) (pos (* mid 2)))
          (cond
            ((< n (vector-ref table pos)) (loop lo (- mid 1)))
            ((> n (vector-ref table (+ pos 1))) (loop (+ mid 1) hi))
            (else #t))))))

(define (unicode-map n table)
  (let ((pos (unicode-find table n 4)))
    (if (and pos (= (modulo (- n (vector-ref table pos))
                           (vector-ref table (+ pos 2))) 0))
        (+ n (vector-ref table (+ pos 3)))
        n)))

(define (unicode-full c table)
  (and (>= (char->integer c) 128)
       (let ((pos (unicode-find table (char->integer c) 2)))
         (and pos (vector-ref table (+ pos 1))))))

(define (unicode-string-case s simple full)
  (let* ((end (string-length s))
         (len (let loop ((i 0) (len 0))
                (if (= i end) len
                    (let ((replacement (unicode-full (string-ref s i) full)))
                      (loop (+ i 1) (+ len (if replacement (string-length replacement) 1)))))))
         (out (make-string len)))
    (let loop ((i 0) (j 0))
      (if (= i end) out
          (let* ((c (string-ref s i)) (replacement (unicode-full c full)))
            (if replacement
                (begin
                  (str-copy-internal out j replacement 0 (string-length replacement))
                  (loop (+ i 1) (+ j (string-length replacement))))
                (begin
                  (string-set! out j (simple c))
                  (loop (+ i 1) (+ j 1)))))))))

(define (string-downcase s) (unicode-string-case s char-downcase unicode-lower-full))
(define (string-upcase s) (unicode-string-case s char-upcase unicode-upper-full))
(define (string-foldcase s) (unicode-string-case s char-foldcase unicode-fold-full))

(define (unicode-string-ci eq lt gt a b)
  (let ((na (string-length a)) (nb (string-length b)))
    (let loop ((i 0))
      (cond
        ((= i na) (if (= i nb) eq lt))
        ((= i nb) gt)
        (else
          (let ((ca (char->integer (string-ref a i)))
                (cb (char->integer (string-ref b i))))
            (if (or (>= ca 128) (>= cb 128))
                (strcmp char=? (lambda (a b) (if (char<? a b) lt gt))
                        eq lt gt (string-foldcase a) (string-foldcase b))
                (let ((ca (if (<= 65 ca 90) (+ ca 32) ca))
                      (cb (if (<= 65 cb 90) (+ cb 32) cb)))
                  (cond ((= ca cb) (loop (+ i 1)))
                        ((< ca cb) lt)
                        (else gt))))))))))
