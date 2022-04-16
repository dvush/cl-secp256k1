(uiop:define-package #:secp256k1-ffi
  (:use #:cl #:cffi)
  (:export
   
   ;; secp256k1.h 
   #:secp256k1-context
   #:secp256k1-scratch-space
   #:secp256k1-pubkey
   #:secp256k1-ecdsa-signature
   #:+secp256k1-flags-type-mask+
   #:+secp256k1-flags-type-context+
   #:+secp256k1-flags-type-compression+
   #:+secp256k1-flags-bit-context-verify+
   #:+secp256k1-flags-bit-context-sign+
   #:+secp256k1-flags-bit-context-declassify+
   #:+secp256k1-flags-bit-compression+
   #:+secp256k1-context-none+
   #:+secp256k1-context-verify+
   #:+secp256k1-context-sign+
   #:+secp256k1-context-declassify+
   #:+secp256k1-ec-uncompressed+
   #:+secp256k1-ec-compressed+
   #:+secp256k1-tag-pubkey-even+
   #:+secp256k1-tag-pubkey-odd+
   #:+secp256k1-tag-pubkey-uncompressed+
   #:+secp256k1-tag-pubkey-hybrid-even+
   #:+secp256k1-tag-pubkey-hybrid-odd+
   #:*secp256k1-context-no-precomp*
   #:secp256k1-context-create
   #:secp256k1-context-clone
   #:secp256k1-context-destroy
   #:secp256k1-context-set-illegal-callback
   #:secp256k1-context-set-error-callback
   #:secp256k1-scratch-space-create
   #:secp256k1-scratch-space-destroy
   #:secp256k1-ec-pubkey-parse
   #:secp256k1-ec-pubkey-serialize
   #:secp256k1-ec-pubkey-cmp
   #:secp256k1-ecdsa-signature-parse-compact
   #:secp256k1-ecdsa-signature-parse-der
   #:secp256k1-ecdsa-signature-serialize-der
   #:secp256k1-ecdsa-signature-serialize-compact
   #:secp256k1-ecdsa-verify
   #:secp256k1-ecdsa-signature-normalize
   #:*secp256k1-nonce-function-rfc6979*
   #:*secp256k1-nonce-function-default*
   #:secp256k1-ecdsa-sign
   #:secp256k1-ec-seckey-verify
   #:secp256k1-ec-pubkey-create
   #:secp256k1-ec-seckey-negate
   #:secp256k1-ec-pubkey-negate
   #:secp256k1-ec-seckey-tweak-add
   #:secp256k1-ec-pubkey-tweak-add
   #:secp256k1-ec-seckey-tweak-mul
   #:secp256k1-ec-pubkey-tweak-mul
   #:secp256k1-context-randomize
   #:secp256k1-ec-pubkey-combine
   #:secp256k1-tagged-sha256

   ;; secp256k1_ecdh.h
   #:*secp256k1-ecdh-hash-function-sha256*
   #:*secp256k1-ecdh-hash-function-default*
   #:secp256k1-ecdh
   
   ;; secp256k1_extrakeys.h
   #:secp256k1-xonly-pubkey
   #:secp256k1-keypair
   #:secp256k1-xonly-pubkey-parse
   #:secp256k1-xonly-pubkey-serialize
   #:secp256k1-xonly-pubkey-cmp
   #:secp256k1-xonly-pubkey-from-pubkey
   #:secp256k1-xonly-pubkey-tweak-add
   #:secp256k1-xonly-pubkey-tweak-add-check
   #:secp256k1-keypair-create
   #:secp256k1-keypair-sec
   #:secp256k1-keypair-pub
   #:secp256k1-keypair-xonly-pub
   #:secp256k1-keypair-xonly-tweak-add

   ;; secp256k1_preallocated.h
   #:secp256k1-context-preallocated-size
   #:secp256k1-context-preallocated-create
   #:secp256k1-context-preallocated-clone-size
   #:secp256k1-context-preallocated-clone
   #:secp256k1-context-preallocated-destroy

   ;; secp256k1_recovery.h
   #:secp256k1-ecdsa-recoverable-signature
   #:secp256k1-ecdsa-recoverable-signature-parse-compact
   #:secp256k1-ecdsa-recoverable-signature-convert
   #:secp256k1-ecdsa-recoverable-signature-serialize-compact
   #:secp256k1-ecdsa-sign-recoverable
   #:secp256k1-ecdsa-recover

   ;;secp256k1_schnorrsig.h
   #:secp256k1-nonce-function-bip340
   #:secp256k1-schnorrsig-extraparams
   #:secp256k1-schnorrsig-sign
   #:secp256k1-schnorrsig-sign-custom
   #:secp256k1-schnorrsig-verify))


(uiop:define-package #:secp256k1
  (:use #:cl #:secp256k1-ffi)
  (:export
   #:incorrect-secret-key-error
   
   #:make-secret-key
   #:secret-key-verify


   #:public-key-parse-error

   #:public-key-create
   #:public-key-parse
   #:public-key-serialize
   #:public-key-eq
   #:public-key-compare
   #:public-key-from-components
   #:public-key-destructure


   #:signature-parse-error
   #:signature-failure-error

   #:signature-serialize
   #:signature-parse
   #:signature-sign
   #:signature-verify
   #:signature-normalize
   #:signature-from-components
   #:signature-destructure


   #:recov-signature-parse-error
   #:recov-signature-failure-error

   #:recov-signature-serialize
   #:recov-signature-parse
   #:recov-signature-sign
   #:recov-signature-recover
   #:recov-signature-destructure
   #:recov-signature-from-components))
