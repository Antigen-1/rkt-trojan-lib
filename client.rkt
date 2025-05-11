#lang racket/base
(require openssl "render.rkt" "data.rkt" racket/port racket/contract racket/tcp)
(provide (contract-out (start-client (->* (string?
                                           string? port-number?
                                           string? port-number?
                                           input-port? output-port?)
                                          (#:context (or/c ssl-client-context? ssl-protocol-symbol/c))
                                         any))))

(define (start-client passwd proxy-address proxy-port dst-address dst-port payload output
                      #:context (ctx 'secure))
  (define-values (in out) (ssl-connect proxy-address proxy-port ctx))
  ;; Check the shape of dst-address
  (define dst-address-type
    (cond ((regexp-match? #px"^[0-9]+(\\.[0-9]+){3}$" dst-address) 'ipv4)
          ((regexp-match? #px"^[0-9a-fA-F]{4}(:[0-9a-fA-F]{4}){7}$" dst-address) 'ipv6)
          (else 'domain)))
  (define send-thd
    (thread
     (lambda ()
       (copy-port (client-data->input-port
                   (client-data passwd
                                (request 'connect dst-address-type dst-address dst-port)
                                payload))
                  out)
       (close-output-port out))))
  (define recv-thd
    (thread (lambda ()
              (copy-port in output)
              (close-output-port output))))
  (let loop ((pool (list recv-thd send-thd)))
    (if (null? pool)
        (void)
        (loop (remove (apply sync pool) pool)))))
