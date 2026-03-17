#lang racket/base
(require openssl "render.rkt" "data.rkt" racket/port racket/contract racket/tcp net/cookies/common net/ip)
(provide (contract-out (start-client (-> (or/c 'connect 'udp-associate)
                                         string?
                                         string? port-number?
                                         string? port-number?
                                         input-port? output-port?
                                         any))))

(define (start-client mode passwd proxy-address proxy-port dst-address dst-port payload output)
  (with-handlers ((exn:fail? (lambda (e) (close-input-port payload) 
                                         (close-output-port output)
                                         (raise e))))
    (define-values (in out) (ssl-connect proxy-address proxy-port 'secure))
    ;; Check the shape of dst-address
    (define-values (dst-address-type dst-address-value)
      (cond ((domain-value? dst-address) (values 'domain dst-address))
            (else (define as (make-ip-address dst-address))
                  (values (case (ip-address-version as)
                            ((4) 'ipv4)
                            ((6) 'ipv6))
                          as))))
    (define exn-ch (make-channel))
    (define send-thd
      (thread
       (lambda ()
         (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
           (dynamic-wind
             void
             (lambda ()
               (copy-port (client-data->input-port
                           (client-data passwd
                                        (request mode dst-address-type dst-address-value dst-port)
                                        payload))
                          out))
            (lambda ()
               (close-input-port payload)
               (close-output-port out)))))))
    (define recv-thd
      (thread (lambda ()
                (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
                  (dynamic-wind
                    void
                    (lambda ()
                      (copy-port in output))
                    (lambda ()
                      (close-input-port in)
                      (close-output-port output)))))))
    (let loop ((pool (list recv-thd send-thd)))
      (if (null? pool)
          (void)
          (let ()
            (define r (apply sync exn-ch pool))
            (cond ((exn? r) 
                   (map kill-thread pool) 
                   (raise r))
                  (else (loop (remove r pool)))))))))
