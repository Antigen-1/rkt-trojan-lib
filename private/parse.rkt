#lang racket/base
(require "data.rkt" file/sha1 net/ip racket/contract)
(provide (contract-out (input-port->server-data (-> string? input-port? server-data?))))

(define (parse-request in)
    (let/cc cc
        (define (exit) (cc #f))
        (define cmd
            (case (read-byte in)
                ((1) 'connect)
                ((3) #;'udp-associate (exit))
                (else (exit))))
        (define dest-type
            (case (read-byte in)
                ((1) 'ipv4)
                ((3) 'domain)
                ((4) 'ipv6)
                (else (exit))))
        (define dest
            (case dest-type
                ((ipv4) 
                 (define bts (read-bytes 4 in))
                 (if (eof-object? bts) (exit) (void))
                 (make-ip-address bts))
                ((ipv6) 
                 (define bts (read-bytes 16 in))
                 (if (eof-object? bts) (exit) (void))
                 (make-ip-address bts))
                ((domain) 
                 (define len (read-byte in))
                 (if (eof-object? len) (exit) (void))
                 (define name (read-bytes len in))
                 (if (and (not (eof-object? name)) (= len (bytes-length name))) (void) (exit))
                 (bytes->string/utf-8 name))))
        (define port
            (let ((f (read-byte in)) (s (read-byte in)))
                (if (or (eof-object? f) (eof-object? s))
                    (exit)
                    (void))
                (bitwise-ior (arithmetic-shift f 8) s)))
        (request cmd dest-type dest port)))

(module+ test
    (require rackunit)
    ;; These tests are ported from render.rkt
    (check-equal?
        (parse-request (open-input-bytes #"\x01\x01\x7f\x00\x00\x01\x00\x50"))
        (request 'connect 'ipv4 (make-ip-address "127.0.0.1") 80))
    (check-equal?
        (request 'connect 'domain "example.top" 80)
        (parse-request (open-input-bytes #"\x01\x03\x0bexample.top\x00\x50")))
    (check-equal?
        (request 'connect 'ipv6 (make-ip-address "2001:0db8:ac10:fe01:0000:0000:0000:0000") 80)
        (parse-request (open-input-bytes #"\x01\x04\x20\x01\x0d\xb8\xac\x10\xfe\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x50")))
        
    (check-false (parse-request (open-input-bytes #"")))
    (check-false (parse-request (open-input-bytes #"\x01")))
    (check-false (parse-request (open-input-bytes #"\x03")))
    (check-false (parse-request (open-input-bytes #"\x01\x01")))
    (check-false (parse-request (open-input-bytes #"\x01\x03\x07")))
    (check-false (parse-request (open-input-bytes #"\x01\x03\x0bexample.top")))
    (check-false (parse-request (open-input-bytes #"\x01\x03\x0bexample.top\x07")))
)

(define (input-port->server-data passwd in)
    (let/cc cc
        (define (exit) (cc #f))
        (define hash (bytes->hex-string (sha224-bytes (open-input-string passwd))))
        (define recv-hash-bytes (read-bytes 56 in))
        (if (or (eof-object? recv-hash-bytes) (not (string=? hash (bytes->string/utf-8 recv-hash-bytes)))) (exit) (void))
        (if (equal? (read-bytes-line in 'return-linefeed) #"")
            (void)
            (exit))
        (define req (parse-request in))
        (and req (equal? (read-bytes-line in 'return-linefeed) #"") (server-data hash req in))))