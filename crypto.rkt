#lang racket/base
(require openssl/libcrypto openssl/sha1
         ffi/unsafe ffi/unsafe/define
         (rename-in racket/contract (-> c:->))
         (except-in racket/contract ->))
(provide (contract-out
          (SHA224-bytes (c:-> bytes? any))
          (SHA224 (c:-> string? any))))

(define-ffi-definer define-crypto libcrypto)

(define-crypto SHA224-bytes
  (_fun (data) ::
        (_bytes = data)
        (_size = (bytes-length data))
        (r : (_bytes o 28))
        -> _pointer
        -> r)
  #:c-id SHA224)
(define (SHA224 str)
  (bytes->hex-string (SHA224-bytes (string->bytes/utf-8 str))))

(module+ test
  (require rackunit)

  (define string "Hello, World!")
  (define digest (SHA224 string))
  (displayln (format "(SHA224 ~s) = ~s" string digest))
  (check-equal? (string-length digest) 56))
