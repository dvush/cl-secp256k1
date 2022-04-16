(asdf:defsystem #:secp256k1
  :description "FFI findings for secp256k1 library"
  :author "Vitaly Drogan <vitaly@dvush.net>"
  :license  "MIT"
  :version "0.1.0"
  :serial t
  :depends-on (#:cffi)
  :components ((:module "src"
		:components
		((:file "package")
		 (:file "secp256k1-ffi")
		 (:file "utils")
		 (:file "secp256k1"))))
  :in-order-to ((asdf:test-op (asdf:test-op #:secp256k1/test))))


(asdf:defsystem #:secp256k1/test
  :depends-on (#:secp256k1 #:parachute #:ironclad #:trivial-benchmark)
  :components ((:module "tests"
		:components
		((:file "package")
		 (:file "secp256k1-test-ffi")
		 (:file "secp256k1-test"))))
  :perform (asdf:test-op (op c) (uiop:symbol-call :parachute :test '(:secp256k1-test :secp256k1-test-ffi))))
