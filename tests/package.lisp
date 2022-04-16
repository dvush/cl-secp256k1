(uiop:define-package #:secp256k1-test-ffi
  (:use #:cl #:secp256k1-ffi #:parachute #:cffi))


(uiop:define-package #:secp256k1-test
  (:use #:cl #:secp256k1 #:parachute)
  (:export
   #:benchmark-report-compare-ironclad))
