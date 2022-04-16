(in-package #:secp256k1-test-ffi)

(define-test secp256k1-ffi)

(define-test test-secp256k1-h
  :parent secp256k1-ffi)

(define-test test-context-lifecycle
  :parent test-secp256k1-h
  (labels ((create-clone-delete-ctx (flags)
	     (let* ((ctx (secp256k1-context-create flags))
		    (cloned-ctx (secp256k1-context-clone ctx)))
	       (false (null-pointer-p ctx))
	       (false (null-pointer-p cloned-ctx))
	       (secp256k1-context-destroy cloned-ctx)
	       (secp256k1-context-destroy ctx))))
    (create-clone-delete-ctx +secp256k1-context-verify+)
    (create-clone-delete-ctx +secp256k1-context-sign+)
    (create-clone-delete-ctx +secp256k1-context-declassify+)
    (create-clone-delete-ctx (logior +secp256k1-context-sign+ +secp256k1-context-verify+))
    (create-clone-delete-ctx +secp256k1-context-none+)))

(defmacro with-context ((ctx &key (flags +secp256k1-context-verify+)) &body body)
  `(let ((,ctx (secp256k1-context-create ,flags)))
     (unwind-protect (progn ,@body)
       (secp256k1-context-destroy ,ctx))))

(define-test test-scratch-space
  :parent test-secp256k1-h
  (with-context (ctx :flags +secp256k1-context-none+)
    (let ((scratch (secp256k1-scratch-space-create ctx 100)))
      (false (null-pointer-p scratch))
      (secp256k1-scratch-space-destroy ctx scratch))))

(defun shareable-byte-vector-from-array (array)
  (loop :with length := (length array)
	:with result := (make-shareable-byte-vector length)
	:for i :below length
	:do (setf (aref result i) (aref array i))
	:finally (return result)))

(defparameter +seckey-1+ (shareable-byte-vector-from-array
			  #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)))

(define-test test-seckey
  :parent test-secp256k1-h
  (let ((correct-seckey (shareable-byte-vector-from-array
			 #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)))
	(tweak (shareable-byte-vector-from-array
		#(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 10))))
    (with-pointer-to-vector-data (sec-ptr correct-seckey)
      (with-pointer-to-vector-data (tweak-ptr tweak)
	(with-context (ctx)
	  (is = 1 (secp256k1-ec-seckey-verify ctx sec-ptr))
	  (is = 1 (secp256k1-ec-seckey-negate ctx sec-ptr))
	  (is = 1 (secp256k1-ec-seckey-negate ctx sec-ptr))
	  (is = 1 (secp256k1-ec-seckey-tweak-add ctx sec-ptr tweak-ptr))
	  (is = 1 (secp256k1-ec-seckey-tweak-mul ctx sec-ptr tweak-ptr)))))))
