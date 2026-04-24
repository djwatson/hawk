(define-library (scheme lazy)
  (import (only (r7expander native) delay delay-force force make-promise promise?))
  (export delay delay-force force make-promise promise?))
