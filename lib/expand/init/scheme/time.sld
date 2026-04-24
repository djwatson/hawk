(define-library (scheme time)
  (import (only (r7expander native) current-jiffy current-second jiffies-per-second))
  (export current-jiffy current-second jiffies-per-second))
