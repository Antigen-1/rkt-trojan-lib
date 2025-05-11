#lang racket/base
(require openssl "render.rkt" "data.rkt" racket/port racket/contract racket/tcp net/cookies/common)
(provide (contract-out (start-client (-> string?
                                         string? port-number?
                                         string? port-number?
                                         input-port? output-port?
                                         any))))

(define (start-client passwd proxy-address proxy-port dst-address dst-port payload output)
  (define-values (in out) (ssl-connect proxy-address proxy-port 'secure))
  ;; Check the shape of dst-address
  (define dst-address-type
    (cond ((regexp-match? #px"^[0-9]+(\\.[0-9]+){3}$" dst-address) 'ipv4)
          ((regexp-match? #px"^[0-9a-fA-F]{4}(:[0-9a-fA-F]{4}){7}$" dst-address) 'ipv6)
          ((domain-value? dst-address) 'domain)
          (else (raise-argument-error 'start-client "ipv4, ipv6 address or (sub)domain name"
                                      dst-address))))
  (define send-thd
    (thread
     (lambda ()
       (dynamic-wind
         void
         (lambda ()
           (copy-port (client-data->input-port
                       (client-data passwd
                                    (request 'connect dst-address-type dst-address dst-port)
                                    payload))
                      out))
         (lambda ()
           (close-input-port payload)
           (close-output-port out))))))
  (define recv-thd
    (thread (lambda ()
              (dynamic-wind
                void
                (lambda ()
                  (copy-port in output))
                (lambda ()
                  (close-input-port in)
                  (close-output-port output))))))
  (let loop ((pool (list recv-thd send-thd)))
    (if (null? pool)
        (void)
        (loop (remove (apply sync pool) pool)))))
