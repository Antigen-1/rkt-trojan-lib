#lang racket/base
(require racket/port racket/contract)
(provide (contract-out (opt:copy-port (->* (input-port? output-port?) (exact-positive-integer?) any))))

(define (opt:copy-port in out (size 4096))
    (define s (make-bytes size))
    (let loop ()
        (define e/n (read-bytes-avail! s in))
        (if (number? e/n)
            (begin (write-bytes s out 0 e/n) (loop))
            ;; Special values will be ignored.
            (void))))

(module+ test
    (require rackunit)
    (define bstr (list->bytes (build-list 10000 (lambda (_) (random 0 255)))))
    (check-equal?
        bstr
        (call-with-output-bytes
            (lambda (out)
                (opt:copy-port (open-input-bytes bstr) out)))))