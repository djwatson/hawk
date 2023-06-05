(define label-to-offset '())
(define offset-to-label '())
(define pending-labels (make-hamt))
(define (add-label c label)
  (if (assoc label label-to-offset) 
    (error "Adding a label twice"))
  (change-label c label))

(define (change-label c label)
  (set! label-to-offset (cons
                         (cons label (get-code-offset c))
                         label-to-offset))
  (set! offset-to-label (cons
                         (cons (get-code-offset c) label)
                         offset-to-label))
  (let ((pending (hamt/get pending-labels label '())))
    (for-each
      (lambda (pending) 
        (emit-fixup c pending (get-code-offset c)))
      pending))
  ;; TODO cleanup pending?
  )

(define (get-label-offset c label)
  (let ((lab (assoc label label-to-offset)))
    (hamt/cons! pending-labels label (get-code-offset c))
    (if lab 
      (cdr lab) -1)))

(define (label-update-caller label old new)
  (define pending (hamt/find pending-labels label))
  (define found (member old pending))
  (if (not found) 
    (error "Could not update label caller: not found"))
  (set-car! found new))

(define (verify-pending-labels)
  (hamt-for-each
    (lambda (k v) 
      (error "Error, pending label: " k v))
    pending-labels))

;; Display some label augmentation for capstone.
;; f - is this a label found as a relative jump?
(define (disassemble_address addr f)
  (let ((label (assoc addr offset-to-label)))
    (if label 
      (begin
        (if f 
          (display "  <"))
        (display (cdr label))
        (if (not f) 
          (display ":\n") (display ">")))
      (if f 
        (display "   ???????????")))))

