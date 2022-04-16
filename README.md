# cl-secp256k1

Common Lisp CFFI bindings to [bitcoin-core/secp256k1](https://github.com/bitcoin-core/secp256k1) library 
that provides public-key cryptography over secp256k1 curve. secp256k1 signatures are used in Bitcoin, Ethereum
and other blockchains.

# Usage

## Install secp256k1 library

See your package manager for installation instructions. 

Note that basic secp256k1 supports only basic signing and verification and recoverable signatures are not supported. All major distributions have all stable features turned on but if you have problems with that build library from source.

Example:

```bash
# Arch Linux
pacman -S libsecp256k1

# Ubuntu 
apt install libsecp256k1-dev 

# macos
brew tap cuber/homebrew-libsecp256k1
brew install libsecp256k1
```

## Use

### Public and secret keys.

```lisp
;; create secret key from 32 byte array
(secp256k1:make-secret-key #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))

;; create public key from secret key
(secp256k1:public-key-create sec-key)

;; parse public key from bytes (see `public-key-serialize` for creating this byte array)
(secp256k1:public-key-parse 
	#(4 121 190 102 126 249 220 187 172 85 160 98 149 206 135 11 7 2 155 252 219 45
		206 40 217 89 242 129 91 22 248 23 152 72 58 218 119 38 163 196 101 93 164
		251 252 14 17 8 168 253 23 180 72 166 133 84 25 156 71 208 143 251 16 212 184))
```

### Signatures and recoverable signatures.

There are 2 types of signatures and methods associated with them: `signature*` and `recov-signature*`.
They both are created using secret key. Signature contains only R and S value and verification assumes knowledge of the public key. Recoverable signature contains R,S and V (recovery id which is 0-3) and recovery procedure returns public key that was used for signature creation.

```lisp
;; signature
(secp256k1:signature-sign message-hash32 secret-key) ; => signature
(secp256k1:signature-verify signature message-hash32 public-key) ; => nil or t

;; recoverable signature
(secp256k1:recov-signature-sign message-hash32 secret-key) ; => recov-signature
(secp256k1:recov-signature-recover recov-signature message-hash32) ; => nil or public key
```

### Serialization and parsing

`public-key`, `signature`, `recov-signature` has data field with internal byte field representation that should not be used for persistance, hashing, etc.

Instead each structure has `*-parse`, `*-serialize` methods for working with portable byte representations and `*-destructure`, `*-from-components` for creating more structured representations.

For example:
```lisp
(secp256k1:public-key-destructure public-key)
;; =>
;; (:X
;;  #(121 190 102 126 249 220 187 172 85 160 98 149 206 135 11 7 2 155 252 219 45
;;    206 40 217 89 242 129 91 22 248 23 152)
;;  :Y
;;  #(72 58 218 119 38 163 196 101 93 164 251 252 14 17 8 168 253 23 180 72 166
;;    133 84 25 156 71 208 143 251 16 212 184))
```

### Conditions

Library raises specific error conditions if signing and parsing fails.

Conditions:
```lisp
incorrect-secret-key-error

public-key-parse-error

signature-parse-error
signature-failure-error

recov-signature-parse-error
recov-signature-failure-error
```

# Misc.

## secp256k1 and secp256k1-ffi

Library has two packages secp256k1-ffi with raw CFFI bindings and secp256k1 with lispy wrapper that takes care of low-level details of CFFI bindings, secp256k1-context managment.

## Benchmarks vs Ironclad

Message signing is ~30 times faster than Ironclad out of the box. AFAIC ironclad does not use deterministic nonce
generation so its numbers could be inflated because of RNG.

```
CL-USER> (secp256k1-test:benchmark-report-compare-ironclad)
secp256k1 signing:
-                SAMPLES  TOTAL     MINIMUM   MAXIMUM   MEDIAN    AVERAGE   DEVIATION  
REAL-TIME        100      0.007999  0         0.001     0         0.00008   0.000271   
RUN-TIME         100      0.00734   0.000072  0.000132  0.000073  0.000073  0.000006   
USER-RUN-TIME    100      0.007338  0.000072  0.000125  0.000073  0.000073  0.000005   
SYSTEM-RUN-TIME  100      0.000006  0         0.000003  0         0.0       0.0        
PAGE-FAULTS      100      0         0         0         0         0         0.0        
GC-RUN-TIME      100      0         0         0         0         0         0.0        
BYTES-CONSED     100      260384    0         32768     0         2603.84   8830.112   
EVAL-CALLS       100      0         0         0         0         0         0.0        

ironclad signing:
-                SAMPLES  TOTAL      MINIMUM   MAXIMUM   MEDIAN    AVERAGE    DEVIATION  
REAL-TIME        100      0.238002   0.002     0.008     0.002     0.00238    0.000892   
RUN-TIME         100      0.236695   0.001912  0.008223  0.002017  0.002367   0.000881   
USER-RUN-TIME    100      0.236744   0.001913  0.008224  0.002018  0.002367   0.000881   
SYSTEM-RUN-TIME  100      0.000011   0         0.000005  0         0.0        0.000001   
PAGE-FAULTS      100      0          0         0         0         0          0.0        
GC-RUN-TIME      100      14.443     0         4.154     0         0.14443    0.603128   
BYTES-CONSED     100      271772736  2586672   2750592   2717440   2717727.3  24254.49   
EVAL-CALLS       100      0          0         0         0         0          0.0        
```
