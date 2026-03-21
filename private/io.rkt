#lang typed/racket/base
(provide opt:copy-port)

(define (opt:copy-port (in : Input-Port) (out : Output-Port) (size : Exact-Positive-Integer 4096)) : Void
    (define s (make-bytes size))
    (let read-loop ()
        (define e/n (read-bytes-avail! s in))
        (if (number? e/n)
            (let write-loop ((wn : Natural 0))
                (if (= wn e/n)
                    (read-loop)
                    (let ((an (write-bytes-avail s out wn e/n)))
                        (write-loop (+ wn an)))))
            ;; Special values will be ignored.
            (void))))

(module* test racket/base
    (require rackunit racket/port (submod ".."))
    (let loop ((n 10))
        (cond ((= n 0) (void))
              (else
                (define bstr (list->bytes (build-list (random 2000 20000) (lambda (_) (random 0 255)))))
                (check-equal?
                    bstr
                    (call-with-output-bytes
                        (lambda (out)
                            (opt:copy-port (open-input-bytes bstr) out))))
                (loop (- n 1))))))