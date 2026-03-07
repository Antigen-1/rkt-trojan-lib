#lang racket/base
(require "parse.rkt" "data.rkt"  racket/match racket/port racket/contract racket/tcp net/ip)
(provide (contract-out (start-server (-> string?
                                         input-port? output-port?
                                         any))))

(define (start-server passwd input output)
  (with-handlers ((exn:fail? (lambda (e) (close-input-port input) 
                                         (close-output-port output)
                                         (raise e))))
    (define data (input-port->server-data passwd input))
    (match data
      (#f (close-input-port input) (close-output-port output))
      ((server-data hash (request cmd dst-type dst port) payload)
       (define-values (in out) (tcp-connect (if (ip-address? dst) (ip-address->string dst) dst) port))
       (define exn-ch (make-channel))
       (define parallel-pool (make-parallel-thread-pool 2))
       (define send-thd
        (thread
          #:pool parallel-pool
          (lambda ()
            (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
              (dynamic-wind
                void
                (lambda ()
                  (copy-port in output))
                (lambda ()
                  (close-input-port in)
                  (close-output-port output)))))))
       (define recv-thd
        (thread (lambda ()
                  (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
                    (dynamic-wind
                      void
                      (lambda ()
                        (copy-port input out))
                      (lambda ()
                        (close-input-port input)
                        (close-output-port out)))))
          #:pool parallel-pool))
      (let loop ((pool (list recv-thd send-thd)))
        (if (null? pool)
            (parallel-thread-pool-close parallel-pool)
            (let ()
              (define r (apply sync exn-ch pool))
              (cond ((exn? r) 
                     (map kill-thread pool) 
                     (parallel-thread-pool-close parallel-pool)
                     (raise r))
                    (else (loop (remove r pool)))))))))))
