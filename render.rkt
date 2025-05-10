#lang racket/base
(require "data.rkt" "crypto.rkt" openssl/sha1 racket/match racket/port racket/contract)
(provide (contract-out (client-data->input-port (-> client-data? any))))

(define (render-request req)
  (match req
    ((struct request (command address-type address port))
     (bytes-append
      (case command
        ((connect) #"\x01")
        #;((udp-associate) #"\x03"))
      (case address-type
        ((ipv4) #"\x01")
        ((domain) #"\x03")
        ((ipv6) #"\x04"))
      (case address-type
        ((ipv4)
         (define r (regexp-match #px"^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$" address))
         (if r
             (let ((ns (map string->number (cdr r))))
               (if (andmap byte? ns)
                   (apply bytes ns)
                   (raise-argument-error 'render-request "ipv4 address" address)))
             (raise-argument-error 'render-request "ipv4 address" address)))
        ((domain)
         (define address-bytes (string->bytes/utf-8 address))
         (bytes-append (bytes (bytes-length address-bytes))
                       address-bytes))
        ((ipv6)
         (define r (regexp-match
                    #px"^([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4}):([0-9a-fA-F]{4})$"
                    address))
         (if r
             (hex-string->bytes (apply string-append (cdr r)))
             (raise-argument-error 'render-request "ipv6 address" address))))
      (bytes (bitwise-and (arithmetic-shift port -8) 255)
             (bitwise-and port 255))))))

(module+ test
  (require rackunit)
  (check-equal?
   (render-request (request 'connect 'ipv4 "127.0.0.1" 80))
   #"\x01\x01\x7f\x00\x00\x01\x00\x50")
  (check-equal?
   (render-request (request 'connect 'domain "example.top" 80))
   #"\x01\x03\x0bexample.top\x00\x50")
  (check-equal?
   (render-request (request 'connect 'ipv6 "2001:0db8:ac10:fe01:0000:0000:0000:0000" 80))
   #"\x01\x04\x20\x01\x0d\xb8\xac\x10\xfe\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50")
  )

(define (client-data->input-port h)
  (match h
    ((struct client-data (passwd request payload))
     (input-port-append
      #t
      (open-input-string (SHA224 passwd))
      (open-input-bytes #"\r\n")
      (open-input-bytes (render-request request))
      (open-input-bytes #"\r\n")
      payload))))
