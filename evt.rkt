#lang racket/base
(require racket/match racket/tcp racket/contract racket/udp
         openssl
         net/ip net/cookies/common)
(provide (contract-out
          (make-tcp-evt evt-maker/c)
          (make-udp-evt evt-maker/c)
          (make-ssl-evt evt-maker/c))
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
     (define stdout (current-output-port))
     (define evt
       (replace-evt
        l
        (lambda (l)
          (let*-values (((in out) (tcp-accept l))
                        ((_ ad) (tcp-addresses in))
                        ((ip) (make-ip-address ad)))
            (if (or (not allow-address?) (allow-address? ip))
                (begin
                  (displayln (format "~a: A connection from ~a is accepted." name (ip-address->string ip))
                             stdout)
                  (handle-evt always-evt (lambda (_) (values in out))))
                (begin
                  (close-input-port in)
                  (close-output-port out)
                  (displayln (format "~a: A connection from ~a is rejected." name (ip-address->string ip))
                             stdout)
                  evt))))))
     evt)))

(define (make-ssl-evt kwargs)
  (match kwargs
    ((hash '#:name name
           '#:local-address local-address
           '#:local-port local-port
           '#:allow-address? allow-address?
           '#:cert cert 
           '#:private private
           #:open)
     (define listener (ssl-listen local-port 5 #f local-address 'secure))
     (if cert (ssl-load-certificate-chain! listener cert) (void))
     (if private (ssl-load-private-key! listener private) (void))
     (define stdout (current-output-port))
     (define evt
       (replace-evt
        listener
        (lambda (listener)
          (let*-values (((in out) (ssl-accept listener))
                        ((_ ad) (ssl-addresses in))
                        ((ip) (make-ip-address ad)))
            (if (or (not allow-address?) (allow-address? ip))
                (begin
                  (displayln (format "~a: A connection from ~a is accepted." name (ip-address->string ip))
                             stdout)
                  (handle-evt always-evt (lambda (_) (values in out))))
                (begin
                  (close-input-port in)
                  (close-output-port out)
                  (displayln (format "~a: A connection from ~a is rejected." name (ip-address->string ip))
                             stdout)
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
     (define out (current-output-port))

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
     (define (parse-non-empty-packet in atype-fallback len-bstr-fallback len-fallback eof-fallback)
       (define atype (read-byte in))
       (case atype
         ((3)
          (read-bytes (read-byte in) in))
         ((1)
          (read-bytes 4 in))
         ((4)
          (read-bytes 16 in))
         (else (atype-fallback atype)))
       (read-bytes 2 in)
       (define len-bstr (read-bytes-line in 'return-linefeed))
       (cond ((not (= (bytes-length len-bstr) 2))
              (len-bstr-fallback len-bstr)))
       (define len (bitwise-ior (arithmetic-shift (bytes-ref len-bstr 0) 8)
                                (bytes-ref len-bstr 1)))
       (define r (read-bytes len in))
       (cond ((eof-object? r) (eof-fallback))
             ((= len (bytes-length r))
              (cond ((= len 0)
                     (parse-non-empty-packet in atype-fallback len-bstr-fallback len-fallback eof-fallback))
                    (else r)))
             (else (len-fallback len r))))

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
                  (parse-non-empty-packet
                   recv-in
                   ;; ATYPE
                   (lambda (atype)
                     (close-output-port n:out)
                     (displayln (format "~a: UDP packet parsing error(atype ~s)." name atype)
                                err)
                     (cc))
                   ;; len bytes
                   (lambda (bstr)
                     (close-output-port n:out)
                     (displayln (format "~a: UDP packet parsing error(length bytes ~s)." name bstr)
                                err)
                     (cc))
                   ;; len
                   (lambda (len bstr)
                     (close-output-port n:out)
                     (displayln (format "~a: UDP packet parsing error(length ~s; data ~s)." name len bstr)
                                err)
                     (cc))
                   ;; EOF
                   (lambda ()
                     ;; n:out has already been closed
                     (displayln (format "~a: A tunnel is closed by peer" name) err)
                     (cc))))
                (udp-send-to u source-address source-port bstr)
                (loop))))))
       (define n:out
         (make-output-port
          (format "~a/recv-out" name)
          always-evt
          recv-out
          (lambda ()
            (if (equal? (current-thread) thd)
                (void)
                (kill-thread thd)))))
       n:out)
     (define (make-send-ports source-address source-port)
       (define-values (in out) (make-pipe))
       (define n:in
         (make-input-port
          (format "~a/send-in" name)
          in
          in
          (lambda ()
            (call-with-semaphore
             ht-sema
             (lambda ()
               (hash-remove! ht (list source-address source-port)))))))
       (values n:in out))

     (define ports-channel (make-channel))
     (void (thread
            (lambda ()
              (define send-buf (make-bytes 1024))
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
                                            (define send-out
                                              (hash-ref ht
                                                        (list source-address source-port)
                                                        #f))
                                            (cond (send-out
                                                   (write-packet send-buf send-out 0 num))
                                                  (else (displayln (format "~a: udp://~a:~a -> udp://~a:~a"
                                                                           name
                                                                           source-address source-port
                                                                           dest-address dest-port)
                                                                   out)
                                                        (define-values (send-in send-out)
                                                          (make-send-ports source-address source-port))
                                                        (define recv-out
                                                          (make-recv-port source-address source-port))
                                                        (write-packet send-buf send-out 0 num)
                                                        (hash-set! ht
                                                                   (list source-address source-port)
                                                                   send-out)
                                                        (channel-put ports-channel
                                                                     (list send-in recv-out)))))))))))))
                (loop)))))

     (handle-evt
      ports-channel
      (lambda (l) (apply values l))))))
