#lang racket/base
(require "data.rkt" "crypto.rkt" racket/match racket/port racket/contract net/ip)
(provide (contract-out (client-data->input-port (-> client-data? any))))

(define (render-request req)
  (match req
    ((struct request (command address-type address port))
     (bytes-append
      (case command
        ((connect) #"\x01")
        ((udp-associate) #"\x03"))
      (case address-type
        ((ipv4) #"\x01")
        ((domain) #"\x03")
        ((ipv6) #"\x04"))
      (case address-type
        ((ipv4 ipv6)
         (ip-address->bytes address))
        ((domain)
         (define address-bytes (string->bytes/utf-8 address))
         (bytes-append (bytes (bytes-length address-bytes))
                       address-bytes))
        )
      (bytes (bitwise-and (arithmetic-shift port -8) 255)
             (bitwise-and port 255))))))

(module+ test
  (require rackunit)
  (check-equal?
   (render-request (request 'connect 'ipv4 (make-ip-address "127.0.0.1") 80))
   #"\x01\x01\x7f\x00\x00\x01\x00\x50")
  (check-equal?
   (render-request (request 'connect 'domain "example.top" 80))
   #"\x01\x03\x0bexample.top\x00\x50")
  (check-equal?
   (render-request (request 'connect 'ipv6 (make-ip-address "2001:0db8:ac10:fe01:0000:0000:0000:0000") 80))
   #"\x01\x04\x20\x01\x0d\xb8\xac\x10\xfe\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50")
  (check-equal?
   (render-request (request 'connect 'ipv6 (make-ip-address "2001:0db8:ac10:fe01:0000:0000:0000:0000") 80))
   (render-request (request 'connect 'ipv6 (make-ip-address "2001:0db8:ac10:fe01::") 80))
   )
  )

(define (client-data->input-port h)
  (match h
    ((struct client-data (passwd request payload))
     (input-port-append
      #f
      (open-input-string (SHA224 passwd))
      (open-input-bytes #"\r\n")
      (open-input-bytes (render-request request))
      (open-input-bytes #"\r\n")
      payload))))
