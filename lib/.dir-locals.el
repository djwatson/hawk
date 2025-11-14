;;; Directory Local Variables for expand project
;;; For more information see (info "(emacs) Directory Variables")

((scheme-mode . ((eval . (add-hook 'after-save-hook #'scm-format-after-save nil t)))))
