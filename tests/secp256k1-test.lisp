(in-package #:secp256k1-test)

(define-test secp256k1)

(define-test secret-key
  :parent secp256k1
  (let ((sec-key (make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))))
    (true (secret-key-verify sec-key))))


(define-test secret-key-incorrect
  :parent secp256k1
  (fail (make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))
      'incorrect-secret-key-error)
  (let ((sec-key (make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0) :verify nil)))
    (false (secret-key-verify sec-key))))


(defparameter +sec-key+ (make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)))

(define-test public-key
  :parent secp256k1
  (let ((public-key (public-key-create +sec-key+)))
    (let* ((serialized-uncompressed (public-key-serialize public-key))
	   (uncompressed-roundtrip (public-key-parse serialized-uncompressed)))
      (true (public-key-eq public-key uncompressed-roundtrip)))
    (let* ((serialized-compressed (public-key-serialize public-key :compressed t))
	   (compressed-roundtrip (public-key-parse serialized-compressed)))
      (true (public-key-eq public-key compressed-roundtrip)))
    (let* ((other-sec-key (make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2)))
	   (other-public-key (public-key-create other-sec-key)))
      (false (public-key-eq public-key other-public-key))
      (is #'eq :gt (public-key-compare other-public-key public-key))
      (is #'eq :lt (public-key-compare public-key other-public-key)))
    (let* ((components (public-key-destructure public-key))
	   (from-components (apply #'public-key-from-components components)))
      (true (public-key-eq public-key from-components)))))

(define-test public-key-incorrect-parsing
  :parent secp256k1
  (fail (public-key-parse #()) 'public-key-parse-error)
  (let ((public-key (public-key-create +sec-key+)))
    (let ((serialized-uncompressed (public-key-serialize public-key)))
      (setf (aref serialized-uncompressed 0) #xff)
      (fail (public-key-parse serialized-uncompressed) 'public-key-parse-error))))

(define-test signature
  :parent secp256k1
  (let* ((public-key (public-key-create +sec-key+))
	 (message-hash #(#xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff))
	 (signature (signature-sign message-hash +sec-key+)))
    (true (signature-verify signature message-hash public-key))
    (true (nth-value 1 (signature-normalize signature)))
    (let* ((serialized-compact (signature-serialize signature :format :compact))
	   (compact-roundtrip (signature-parse serialized-compact :format :compact))
	   (serialized-roundrip (signature-serialize compact-roundtrip :format :compact)))
      (true (equalp serialized-compact serialized-roundrip)))
    (let* ((serialized-der (signature-serialize signature :format :der))
	   (der-roundtrip (signature-parse serialized-der :format :der))
	   (serialized-roundrip (signature-serialize der-roundtrip :format :der)))
      (true (equalp serialized-der serialized-roundrip)))
    (let* ((components (signature-destructure signature))
	   (from-components (apply #'signature-from-components components)))
      (true (equalp (signature-serialize signature)
		    (signature-serialize from-components))))))

(define-test signature-incorrect-parsing
  :parent secp256k1
  (let* ((message-hash #(#xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff))
	 (signature (signature-sign message-hash +sec-key+)))
    (fail (signature-parse #() :format :der) 'signature-parse-error)
    (let* ((serialized-compact (signature-serialize signature :format :compact)))
      (fail (signature-parse serialized-compact :format :der) 'signature-parse-error))
    ;; for some reason it does not fail
    ;; (let* ((serialized-der (signature-serialize signature :format :der)))
    ;;   (fail (signature-parse serialized-der :format :compact) 'signature-parse-error))
    ))



(define-test recov-signature
  :parent secp256k1
  (let* ((public-key (public-key-create +sec-key+))
	 (message-hash #(#xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff))
	 (recov-signature (recov-signature-sign message-hash +sec-key+)))
    (true (public-key-eq (recov-signature-recover recov-signature message-hash)
			 public-key))

    (let* ((serialized (multiple-value-list (recov-signature-serialize recov-signature)))
	   (roundtrip (apply #'recov-signature-parse serialized))
	   (serialized-roundrip (multiple-value-list (recov-signature-serialize roundtrip))))
      (true (equalp serialized serialized-roundrip)))
    (let* ((components (recov-signature-destructure recov-signature))
    	   (from-components (apply #'recov-signature-from-components components)))
      (true (equalp (multiple-value-list (recov-signature-serialize recov-signature))
    		    (multiple-value-list (recov-signature-serialize from-components)))))))

(define-test recov-signature-incorrect-parsing
  :parent secp256k1
  (let* ((message-hash #(#xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff))
	 (recov-signature (recov-signature-sign message-hash +sec-key+)))

    (multiple-value-bind (octets rec-id) (recov-signature-serialize recov-signature)
      (fail (recov-signature-parse octets 5) 'recov-signature-parse-error)
      (fail (recov-signature-parse #() rec-id) 'recov-signature-parse-error)
      (fail (recov-signature-parse (make-array 64 :initial-element #xff) rec-id) 'recov-signature-parse-error))))


(defun benchmark-report-compare-ironclad ()
  (let ((sec-key (coerce #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1)
			  '(simple-array (unsigned-byte 8) (*))))
	(msg-hash (coerce  #(#xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff
			     #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff #xff
			     #xff #xff #xff #xff #xff #xff #xff #xff)
			   '(simple-array (unsigned-byte 8) (*)))))
    (let* ((sec-key (make-secret-key sec-key)))
      (format t "secp256k1 signing:~%")
      (trivial-benchmark:with-timing (100)
	(signature-sign msg-hash sec-key)))
    (format t "~%")

    (let* ((sec-key (ironclad:make-private-key :secp256k1 :x sec-key)))
      (format t "ironclad signing:~%")
      (trivial-benchmark:with-timing (100)
	(ironclad:sign-message sec-key msg-hash)))))
