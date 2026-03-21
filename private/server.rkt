#lang racket/base
(require "parse.rkt" "data.rkt" "io.rkt" "config.rkt" racket/match racket/port racket/contract racket/tcp net/ip)
(provide (contract-out (start-server (-> string? 'connect
                                         input-port? output-port?
                                         any))))

(define (start-server passwd mode input output)
  (with-handlers ((exn:fail? (lambda (e) (close-input-port input) 
                                         (close-output-port output)
                                         (raise e))))
    (define data (input-port->server-data passwd input))
    (define sz (current-buffer-size))
    (match data
      (#f (close-input-port input) (close-output-port output))
      ((server-data hash (request (? (lambda (cmd) (eq? cmd mode)) _) dst-type dst port) payload)
       (define-values (in out) (tcp-connect (if (ip-address? dst) (ip-address->string dst) dst) port))
       (define exn-ch (make-channel))
       (define send-thd
        (thread
          (lambda ()
            (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
              (dynamic-wind
                void
                (lambda ()
                  (opt:copy-port in output sz))
                (lambda ()
                  (close-input-port in)
                  (close-output-port output)))))))
       (define recv-thd
        (thread (lambda ()
                  (with-handlers ((exn:fail? (lambda (e) (channel-put exn-ch e))))
                    (dynamic-wind
                      void
                      (lambda ()
                        (opt:copy-port input out sz))
                      (lambda ()
                        (close-input-port input)
                        (close-output-port out)))))))
      (let loop ((pool (list recv-thd send-thd)))
        (if (null? pool)
            (void)
            (let ()
              (define r (apply sync exn-ch pool))
              (cond ((exn? r) 
                     (map kill-thread pool) 
                     (raise r))
                    (else (loop (remove r pool)))))))))))
