#lang racket/base
(require racket/match racket/tcp racket/contract racket/udp racket/port racket/exn
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
     ;; A hash table used to dispatch datagrams received locally
     #; (hash/c (list/c string? port-number?) output-port?)
     (define ht (make-hash))
     (define ht-sema (make-semaphore 1))

     (define err (current-error-port))

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
       (define len (- end start))
       (write-byte (arithmetic-shift len -8) out)
       (write-byte (bitwise-and len 255) out)
       (write-bytes #"\r\n" out)
       (write-bytes bstr out start end))
     (define (parse-packet in fallback)
       (define atype (read-byte in))
       (case atype
         ((3)
          (read-bytes (read-byte in) in))
         ((1)
          (read-bytes 4 in))
         ((4)
          (read-bytes 16 in))
         (else (fallback atype)))
       (read-bytes 2 in)
       (define len (+ (arithmetic-shift (read-byte in) 8)
                      (read-byte in)))
       (read-bytes-line in 'return-linefeed)
       (read-bytes len in))

     ;; Receive from the proxy server
     ;; There is also a header in each received packet
     (define (make-recv-port source-address source-port)
       (define-values (recv-in recv-out) (make-pipe))
       (define thd
         (thread
          (lambda ()
            (let/cc cc
              (let loop ()
                (define bstr
                  (parse-packet
                   recv-in
                   (lambda (atype)
                     (close-output-port n:out)
                     (displayln (format "~a: UDP packet parsing error(atype ~s)." name atype)
                                err)
                     (cc))))
                (if (eof-object? bstr)
                    (begin
                      (displayln (format "~a: A tunnel is closed by peer" name) err)
                      (cc))
                    (void))
                (if (= 0 (bytes-length bstr))
                    (void)
                    (udp-send-to u source-address source-port bstr))
                (loop))))))
       (define n:out
         (make-output-port
          (format "~a/recv-out" name)
          always-evt
          recv-out
          (lambda ()
            ;; Clean all objects
            (close-output-port recv-out)
            (call-with-semaphore
             ht-sema
             (lambda ()
               (define send-out
                 (hash-ref ht (list source-address source-port)
                           #f))
               (cond (send-out => close-output-port))
               (hash-remove! ht (list source-address source-port)))))))
       n:out)

     (define ports-channel (make-channel))
     (void (thread
            (lambda ()
              (define send-buf (make-bytes 1024))
              (let loop ()
                (with-handlers ((exn:fail?
                                 (lambda (e)
                                   (displayln (format "~a: ~a" name (exn->string e))
                                              err))))
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
                                              (define send-out
                                                (hash-ref ht
                                                          (list source-address source-port)
                                                          #f))
                                              (cond (send-out
                                                     (write-packet send-buf send-out 0 num))
                                                    (else (define-values (send-in send-out)
                                                            (make-pipe))
                                                          (define recv-out
                                                            (make-recv-port source-address source-port))
                                                          (write-packet send-buf send-out 0 num)
                                                          (hash-set! ht
                                                                     (list source-address source-port)
                                                                     send-out)
                                                          (channel-put ports-channel
                                                                       (list send-in recv-out))))))))))))))
                (loop)))))

     (handle-evt
      ports-channel
      (lambda (l) (apply values l))))))
