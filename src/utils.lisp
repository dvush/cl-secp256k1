(in-package :secp256k1)

(defmacro with-foreign-byte-array ((var lisp-array &optional size) &body body)
  (declare (type (or integer null) size))
  (let ((length-sym (gensym "length")))
    (if size
	(progn
	  `(cffi:with-foreign-array (,var ,lisp-array '(:array :uchar ,size))
	     (progn ,@body)))
	`(let ((,length-sym (length ,lisp-array)))
	   (cffi:with-foreign-object (,var :uchar ,length-sym)
	     (loop :for i :below ,length-sym
		   :do (setf (cffi:mem-aref ,var :uchar i) (aref ,lisp-array i)))
	     (progn ,@body))))))

(defun sharable-byte-array-from-array (array size)
  (assert (= (length array) size) (array))
  (loop :with result := (cffi:make-shareable-byte-vector size)
		    :for i :below size
	:do (setf (aref result i) (aref array i))
	:finally (return result)))

(defmacro with-pointer-to-vector-data-slot ((pointer-sym slot) object-sym &body body)
  (let ((slot-bound-sym (gensym "slot")))
    `(with-slots ((,slot-bound-sym ,slot)) ,object-sym
       (cffi:with-pointer-to-vector-data (,pointer-sym ,slot-bound-sym)
	 (progn ,@body)))))
