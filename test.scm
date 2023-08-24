(do ((i 0 (+ i 1)))
    ((= i 300))
  ($write (remainder i 10) (current-output-port)))
