#lang racket/base
(require racket/match racket/tcp racket/contract racket/udp
         "logging.rkt"
         net/ip net/cookies/common)
(provide (contract-out
          (make-tcp-evt evt-maker/c))
         evt-maker/c)

(define evt-maker/c
  (-> (hash/c keyword? any/c)
      (evt/c input-port? output-port?)))

(define (make-tcp-evt kwargs)
  (match kwargs
    ((hash '#:name name
           '#:local-address local-address
           '#:local-port local-port
           '#:allow-address? allow-address?
           #:open)
     (define l (tcp-listen local-port 4 #f local-address))
     (define evt
       (replace-evt
        l
        (lambda (l)
          (let*-values (((in out) (tcp-accept l))
                        ((_ ad) (tcp-addresses in))
                        ((ip) (make-ip-address ad)))
            (if (or (not allow-address?) (allow-address? ip))
                (begin
                  (report name 'info (format "A connection from ~a is accepted.\n" (ip-address->string ip)))
                  (handle-evt always-evt (lambda (_) (values in out))))
                (begin
                  (close-input-port in)
                  (close-output-port out)
                  (report name 'info (format "A connection from ~a is rejected.\n" (ip-address->string ip)))
                  evt))))))
     evt)))

