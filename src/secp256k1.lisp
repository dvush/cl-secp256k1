(in-package #:secp256k1)

(defvar *ctx* nil)

(defun ensure-context ()
  (unless *ctx*
    (setf *ctx* (secp256k1-context-create (logior +secp256k1-context-sign+
						  +secp256k1-context-verify+))))
  *ctx*)

(defclass secret-key ()
  ((data :initarg :data :type (vector (unsigned-byte 8))
	 :documentation "cffi-shareable 32 byte array can be used as a portable representation")))

(define-condition incorrect-secret-key-error (error) ())

(defun make-secret-key (array &key (verify t))
  "Creates secret key from 32 byte array, if verify is true key will be checked for validity"
  (let* ((data (sharable-byte-array-from-array array 32))
	 (secret-key (make-instance 'secret-key :data data)))
    (when verify
      (unless (secret-key-verify secret-key)
	(error 'incorrect-secret-key-error)))
    secret-key))

(defmethod secret-key-verify ((key secret-key))
  "Checks if secret key is valid"
  (with-pointer-to-vector-data-slot (secret-key-ptr data) key
    (= 1 (secp256k1-ec-seckey-verify (ensure-context) secret-key-ptr))))

(defclass public-key ()
  ((data :initarg :data :type (vector (unsigned-byte 8))
	 :documentation "internal representation as cffi-shareable 64 byte array
Use `public-key-serialize' and `public-key-parse' to work with portable byte representation")))

(define-condition public-key-parse-error (error) ())

(defun make-public-key ()
  (make-instance 'public-key :data (cffi:make-shareable-byte-vector 64)))

(defmethod public-key-compare ((public-key-1 public-key) (public-key-2 public-key))
  "Compares public key, returns one of the following:
:eq (1 = 2), :lt (1 < 2), :gt (1 > 2)"
  (with-pointer-to-vector-data-slot (public-key-1-ptr data) public-key-1
    (with-pointer-to-vector-data-slot (public-key-2-ptr data) public-key-2
      (let ((result (secp256k1-ec-pubkey-cmp (ensure-context)
					     public-key-1-ptr
					     public-key-2-ptr)))
	(cond ((zerop result) :eq)
	      ((< result 0) :lt)
	      ((> result 0) :gt))))))

(defmethod public-key-eq ((public-key-1 public-key) (public-key-2 public-key))
  "Checks if two Public Keyr are equal"
  (eq :eq (public-key-compare public-key-1 public-key-2)))

(defmethod public-key-create ((secret-key secret-key))
  "Creates public key from corresponding secret key"
  (let ((public-key (make-public-key)))
    (with-pointer-to-vector-data-slot (public-key-ptr data) public-key
      (with-pointer-to-vector-data-slot (secret-key-ptr data) secret-key
	(secp256k1-ec-pubkey-create (ensure-context) public-key-ptr secret-key-ptr)))
    public-key))


(defun public-key-parse (octets)
  "Parse Public Key from octet array, raises `public-key-parse-error' if parsing is impossible.
Input should be 32 bytes for compressed representation or 65 for uncompressed one.
see `public-key-serialize' for reverse function.
Uncompressed format is (0x04 ++ x ++ y)"
  (let ((public-key (make-public-key)))
    (with-pointer-to-vector-data-slot (public-key-ptr data) public-key
      (with-foreign-byte-array (octets-ptr octets)
	(unless (= 1 (secp256k1-ec-pubkey-parse (ensure-context) public-key-ptr octets-ptr (length octets)))
	  (error 'public-key-parse-error))))
    public-key))

(defmethod public-key-serialize ((public-key public-key) &key (compressed nil))
  "Serialize Public Key to octet array. If compressed is true output is 32 bytes otherwise its 65
see `public-key-parse' for reverse function
Uncompressed format is (0x04 ++ x ++ y).
"
  (let* ((output-length (if compressed 33 65))
	 (output (cffi:make-shareable-byte-vector output-length))
	 (flags (if compressed +secp256k1-ec-compressed+ +secp256k1-ec-uncompressed+)))
    (with-pointer-to-vector-data-slot (public-key-ptr data) public-key

      (cffi:with-pointer-to-vector-data (output-ptr output)
	(cffi:with-foreign-object (output-length-ptr '(:pointer :size))
	  (setf (cffi:mem-ref output-length-ptr :size) output-length)
	  (secp256k1-ec-pubkey-serialize (ensure-context)
					 output-ptr
					 output-length-ptr
					 public-key-ptr
					 flags))))
    output))

(defmethod public-key-destructure ((public-key public-key))
  "Returns plist wish :x and :y components of public key.
Components are 32 byte arrays."
  (let ((octets (public-key-serialize public-key :compressed nil)))
    (list :x (subseq octets 1 33)
	  :y (subseq octets 33))))

(defun public-key-from-components (&key x y)
  "Create public key from X and Y components.
Components are 32 byte arrays.
"
  (let ((octets (make-array 65 :element-type '(unsigned-byte 8))))
    (setf (aref octets 0) #x04)
    (loop :for i :below 32
	  :do (setf (aref octets (+ i 1)) (aref x i)))
    (loop :for i :below 32
	  :do (setf (aref octets (+ i 33)) (aref y i)))
    (public-key-parse octets)))

(defclass signature ()
  ((data :initarg :data :type (vector (unsigned-byte 8))
	 :documentation "internal representation as cffi-shareable 64 byte array
Use `signature-serialize' and `signature-parse' to work with portable byte representation"
	 )))

(define-condition signature-parse-error (error) ((format :initarg :format)))
(define-condition signature-failure-error (error) ())

(defun make-signature ()
  (make-instance 'signature :data (cffi:make-shareable-byte-vector 64)))


(defmethod signature-serialize ((signature signature) &key (format :compact))
  "Serialize signature to portable octet representation.
Possible formats are :compact (64 bytes - r ++ s),
:der (up to 71 bytes, see DER format for details)"
  (let* ((output-length (ecase format
			  (:compact 64)
			  (:der 71)))
	 (output (cffi:make-shareable-byte-vector output-length)))
    (with-pointer-to-vector-data-slot (signature-ptr data) signature
      (cffi:with-pointer-to-vector-data (output-ptr output)
	(ecase format
	  (:compact
	   (secp256k1-ecdsa-signature-serialize-compact (ensure-context) output-ptr signature-ptr)
	   output)
	  (:der
	   (cffi:with-foreign-object (output-length-ptr '(:pointer :size))
	     (setf (cffi:mem-ref output-length-ptr :size) output-length)
	     (unless (= 1 (secp256k1-ecdsa-signature-serialize-der (ensure-context) output-ptr output-length-ptr signature-ptr))
	       (error "Bug in lisp wrapper, not enough space for signature DER serialization"))
	     (let ((result-length (cffi:mem-ref output-length-ptr :size)))
	       (subseq output 0 result-length)))))))))

(defun signature-parse (octets &key (format :compact))
  "Parse signature from portable octet representation, raises `signature-parse-error' if signature cannot be parsed.
Possible formats are :compact (64 bytes - r ++ s),
:der (up to 71 bytes, see DER format for details)"
  (let ((signature (make-signature)))
    (ecase format
      (:compact
       (with-pointer-to-vector-data-slot (signature-ptr data) signature
	 (with-foreign-byte-array (octets-ptr octets 64)
	   (unless (= 1 (secp256k1-ecdsa-signature-parse-compact (ensure-context)
								 signature-ptr
								 octets-ptr))
	     (error 'signature-parse-error :format format)))))
      (:der
       (with-pointer-to-vector-data-slot (signature-ptr data) signature
	 (with-foreign-byte-array (octets-ptr octets)
	   (unless (= 1 (secp256k1-ecdsa-signature-parse-der (ensure-context)
							     signature-ptr
							     octets-ptr
							     (length octets)))
	     (error 'signature-parse-error :format format))))))
    signature))


(defmethod signature-normalize ((signature signature))
  "Returns signature normalize to cannonical lower-S form original signature is not modified.
Signatures created by this library are always normalized. Signatures that are not normalized would not be verified.
Second value indicates if signature was already normalized."
  (let ((normalized-sig (make-signature)))
    (with-pointer-to-vector-data-slot (normalized-sig-ptr data) normalized-sig
      (with-pointer-to-vector-data-slot (signature-ptr data) signature
	(values normalized-sig (= 0 (secp256k1-ecdsa-signature-normalize (ensure-context)
									 normalized-sig-ptr
									 signature-ptr)))))))


(defmethod signature-sign (message-hash32 (secret-key secret-key))
  "Signs message hash using secret key, raises `signature-failure-error' if message can't be signed (e.g. invalid secret key).
Message should be hashed separatly and 32-byte octet array os hash is passed to this function."
  (let ((signature (make-signature)))
    (with-foreign-byte-array (message-hash32-ptr message-hash32 32)
      (with-pointer-to-vector-data-slot (secret-key-ptr data) secret-key
	(with-pointer-to-vector-data-slot (signature-ptr data) signature
	  (unless (= 1 (secp256k1-ecdsa-sign (ensure-context)
					     signature-ptr
					     message-hash32-ptr
					     secret-key-ptr
					     (cffi:null-pointer)
					     (cffi:null-pointer)))
	    (error 'signature-failure-error)))))
    signature))

(defmethod signature-verify ((signature signature) message-hash32 (public-key public-key))
  "Verifies message signature of given message hash and public key.
Message should be hashed separatly and 32-byte octet array os hash is passed to this function."
  (with-pointer-to-vector-data-slot (signature-ptr data) signature
    (with-pointer-to-vector-data-slot (public-key-ptr data) public-key
      (with-foreign-byte-array (message-hash32-ptr message-hash32 32)
	(= 1 (secp256k1-ecdsa-verify (ensure-context)
				     signature-ptr
				     message-hash32-ptr
				     public-key-ptr))))))

(defmethod signature-destructure ((signature signature))
  "Returns plist with :r (32 bytes) :s (32 bytes)"
  (let ((octets (signature-serialize signature :format :compact)))
    (list :r (subseq octets 0 32)
	  :s (subseq octets 32 64))))

(defun signature-from-components (&key r s)
  "Creates signature from components
:r (32 bytes) :s (32 bytes)"
  (let ((octets (make-array 64 :element-type '(unsigned-byte 8))))
    (loop :for i :below 32
	  :do (setf (aref octets i) (aref r i)))
    (loop :for i :below 32
	  :do (setf (aref octets (+ i 32)) (aref s i)))
    (signature-parse octets :format :compact)))

(defclass recov-signature ()
  ((data :initarg :data :type (vector (unsigned-byte 8))
	 :documentation "internal representation as cffi-shareable 65 byte array
Use `recov-signature-serialize' and `recov-signature-parse' to work with portable byte representation")))

(define-condition recov-signature-parse-error (error) ())
(define-condition recov-signature-failure-error (error) ())

(defun make-recov-signature ()
  (make-instance 'recov-signature :data (cffi:make-shareable-byte-vector 65)))

(defmethod recov-signature-serialize ((recov-signature recov-signature))
  "Serialize recoverable signature to portable octet representation.
Returns 64 byte array and integer recovery id (0, 1, 2, 3)"
  (let* ((output (cffi:make-shareable-byte-vector 64)))
    (with-pointer-to-vector-data-slot (recov-signature-ptr data) recov-signature
      (cffi:with-pointer-to-vector-data (output-ptr output)
	(cffi:with-foreign-object (rec-id-ptr '(:pointer :int))
	  (secp256k1-ecdsa-recoverable-signature-serialize-compact (ensure-context)
								   output-ptr
								   rec-id-ptr
								   recov-signature-ptr)
	  (values output (cffi:mem-ref rec-id-ptr :int)))))))

(defun recov-signature-parse (octets recovery-id)
  "Parse recoverable signature from portable octet representation and recovery id (0, 1, 2, 3).
raises `recov-signature-parse-error' if signature can't be parsed"
  (assert (<= 0 recovery-id 3) (recovery-id) 'recov-signature-parse-error)
  (assert (= (length octets) 64) (octets) 'recov-signature-parse-error)
  (let ((recov-signature (make-recov-signature)))

    (with-pointer-to-vector-data-slot (recov-signature-ptr data) recov-signature
	 (with-foreign-byte-array (octets-ptr octets 64)
	   (unless (= 1 (secp256k1-ecdsa-recoverable-signature-parse-compact (ensure-context)
									     recov-signature-ptr
									     octets-ptr
									     recovery-id))
	     (error 'recov-signature-parse-error))))
    recov-signature))

(defmethod recov-signature-sign (message-hash32 (secret-key secret-key))
  "Creates recoverable signature from message hash using secret key, raises `recov-signature-failure-error' if message can't be signed (e.g. invalid secret key).
Message should be hashed separatly and 32-byte octet array os hash is passed to this function."
  (let ((recov-signature (make-recov-signature)))
    (with-foreign-byte-array (message-hash32-ptr message-hash32 32)
      (with-pointer-to-vector-data-slot (secret-key-ptr data) secret-key
	(with-pointer-to-vector-data-slot (recov-signature-ptr data) recov-signature
	  (unless  (= 1 (secp256k1-ecdsa-sign-recoverable (ensure-context)
							   recov-signature-ptr
							   message-hash32-ptr
							   secret-key-ptr
							   (cffi:null-pointer)
							   (cffi:null-pointer)))
	    (error 'recov-signature-failure-error)))))
    recov-signature))

(defmethod recov-signature-recover ((recov-signature recov-signature) message-hash32)
  "Returns public key used for signature of the given message hash or nil if public key can't be recovered or signature is incorrect.
Message should be hashed separatly and 32-byte octet array os hash is passed to this function."
  (let ((public-key (make-public-key)))
    (with-pointer-to-vector-data-slot (recov-signature-ptr data) recov-signature
      (with-pointer-to-vector-data-slot (public-key-ptr data) public-key
	(with-foreign-byte-array (message-hash32-ptr message-hash32 32)
	  (when  (= 1 (secp256k1-ecdsa-recover (ensure-context)
					       public-key-ptr
					       recov-signature-ptr
					       message-hash32-ptr))
	    public-key))))))

(defmethod recov-signature-destructure ((recov-signature recov-signature))
  "Returns plist with :r (32 bytes) :s (32 bytes) :v (0-3)"
  (multiple-value-bind (octets recodery-id) (recov-signature-serialize recov-signature)
    (list :r (subseq octets 0 32)
	  :s (subseq octets 32 64)
	  :v recodery-id)))

(defmethod recov-signature-destructure* ((recov-signature recov-signature))
  "Returns r s v as multiple values"
  (multiple-value-bind (octets recodery-id) (recov-signature-serialize recov-signature)
    (values (subseq octets 0 32) (subseq octets 32 64) recodery-id)))

(defun recov-signature-from-components (&key r s v)
  "Creates recoverable signature from components
:r (32 bytes) :s (32 bytes) :v (0-3)"
  (let ((octets (make-array 64 :element-type '(unsigned-byte 8))))
    (loop :for i :below 32
	  :do (setf (aref octets i) (aref r i)))
    (loop :for i :below 32
	  :do (setf (aref octets (+ i 32)) (aref s i)))
    (recov-signature-parse octets v)))
