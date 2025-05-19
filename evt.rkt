#lang racket/base
(require racket/match racket/tcp racket/contract racket/udp racket/port
         net/ip net/cookies/common)
(provide (contract-out
          (make-tcp-evt evt-maker/c)
          (make-udp-evt evt-maker/c)))

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
                (handle-evt always-evt (lambda (_) (values in out)))
                (begin
                  (close-input-port in)
                  (close-output-port out)
                  (displayln (format "~a: A connection from ~a is rejected." name (ip-address->string ip)))
                  evt))))))
     evt)))

(define (make-udp-evt kwargs)
  (match kwargs
    ((hash '#:name name
           '#:local-address local-address
           '#:local-port local-port
           '#:dest-address dest-address
           '#:dest-port dest-port
           '#:allow-address? allow-address?
           #:open)
     #; (hash/c (list/c string? port-number?) (list input-port? output-port?))
     (define ht (make-hash))
     (define ht-sema (make-semaphore 1))

     (define u (udp-open-socket local-address local-port))
     (udp-bind! u local-address local-port)

     (define atype+addr+port
       (bytes-append
        (cond ((domain-value? dest-address)
               (define bstr (string->bytes/utf-8 dest-address))
               (bytes-append #"\x03"
                             (bytes (bytes-length bstr))
                             bstr))
              (else (define ip (make-ip-address dest-address))
                    (bytes-append
                     (cond ((ipv4-address? ip) #"\x01")
                           (else #"\x04"))
                     (ip-address->bytes ip))))
        (bytes
         (arithmetic-shift dest-port -8)
         (bitwise-and dest-port 255))))
     (define (write-packet bstr out start end)
       (write-bytes atype+addr+port out)
       (define len (bytes-length bstr))
       (write-byte (arithmetic-shift len -8) out)
       (write-byte (bitwise-and len 255) out)
       (write-bytes #"\r\n" out)
       (write-bytes bstr out))

     ;; Receive from the proxy server
     (define (make-recv-ports source-address source-port)
       (define n:out
         (make-output-port
          (format "~a/recv-out" name)
          always-evt
          (lambda (bstr start end keep? block?)
            ((if block?
                 udp-send-to/enable-break
                 udp-send-to)
             u source-address source-port bstr start end)
            (- end start))
          (lambda ()
            (call-with-semaphore
             ht-sema
             (lambda ()
               (hash-remove! ht (list source-address source-port)))))))
       (values (open-input-nowhere) n:out))

     (define ports-channel (make-channel))
     (void (thread
            (lambda ()
              (define send-buf (make-bytes (sub1 (arithmetic-shift 1 16))))
              (let loop ()
                (sync
                 ;; Send to the proxy server
                 (handle-evt (udp-receive!-evt u send-buf)
                             (lambda (l)
                               (match l
                                 ((list num source-address source-port)
                                  (cond ((allow-address? (make-ip-address source-address))
                                         (call-with-semaphore
                                          ht-sema
                                          (lambda ()
                                            (match-define (list _ send-out)
                                              (hash-ref ht
                                                        (list source-address source-port)
                                                        (list #f #f)))
                                            (cond (send-out
                                                   (write-packet send-buf send-out 0 num))
                                                  (else (define-values (send-in send-out)
                                                          (make-pipe))
                                                        (define-values (recv-in recv-out)
                                                          (make-recv-ports source-address source-port))
                                                        (write-packet send-buf send-out 0 num)
                                                        (hash-set! ht
                                                                   (list source-address source-port)
                                                                   (list recv-in send-out))
                                                        (channel-put ports-channel
                                                                     (list send-in recv-out))))))))))))

                 )
                (loop)))))

     (handle-evt
      ports-channel
      (lambda (l) (apply values l))))))
