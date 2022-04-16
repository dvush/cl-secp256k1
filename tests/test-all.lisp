(in-package :secp256k1-test-all)

(defun asdf-test-system ()
  (let ((report (test '(:secp256k1-test :secp256k1-test-ffi))))
    (unless (eq :passed (status report))
      (warn "Tests failed"))))


