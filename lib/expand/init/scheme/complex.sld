(define-library (scheme complex)
  (import (only (r7expander native)
                angle
                magnitude
                imag-part
                make-polar
                make-rectangular
                real-part))
  (export angle magnitude imag-part make-polar make-rectangular real-part))
