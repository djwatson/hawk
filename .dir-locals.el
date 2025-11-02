((c-mode . ((before-save-hook . (lambda ()
                                  (when (derived-mode-p 'c-mode)
                                    (clang-format-buffer))))))
)
