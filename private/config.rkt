#lang racket/base
(require racket/match racket/tcp
         (prefix-in m: racket/match)
         (for-syntax racket/base))
(provide (all-defined-out))

(define default-config
  #hash(("password" . "abcdefg")
        ("remote-address" . "example1.com")
        ("remote-port" . 1080)
        ("tunnels"
         .
         (#hash(("name" . "tunnel1")
                ("mode" . "connect")
                ("dest-address" . "example2.com")
                ("dest-port" . 8080)
                ("local-address" . "127.0.0.1")
                ("local-port" . 8080)
                ("allow" . (("127.0.0.0" "255.0.0.0")))
                ("block" . #f))))))
(define default-server-config
  #hash(("password" . "abcdefg")
        ("proxy-address" . "127.0.0.1")
        ("proxy-port" . 9000)
        ("allow" . (("127.0.0.0" "255.0.0.0")))
        ("block" . #f)
        ("cert" . #f)
        ("private" . #f)))

(define-match-expander config-pattern
  (lambda (stx)
    (syntax-case stx ()
      [(_ password remote-address remote-port tunnels)
       #'(hash "password" (? string? password)
               "remote-address" (? string? remote-address)
               "remote-port" (? port-number? remote-port)
               "tunnels" (? list? tunnels)
               #:closed)])))
(define-match-expander tunnel-pattern
  (lambda (stx)
    (syntax-case stx ()
      [(_ name mode dest-address dest-port local-address local-port allow-network block-network)
       #'(hash "name" (? string? name)
               "mode" (and (or "connect" "udp-associate") mode)
               "dest-address" (? string? dest-address)
               "dest-port" (? port-number? dest-port)
               "local-address" (? string? local-address)
               "local-port" (? listen-port-number? local-port)
               "allow" (or (and #f allow-network) (? list? allow-network))
               "block" (or (and #f block-network) (? list? block-network))
               #:closed)])))
(define-match-expander server-config-pattern
  (lambda (stx)
    (syntax-case stx ()
      [(_ password address port allow-network block-network cert private)
       #'(hash "password" (? string? password)
               "proxy-address" (? string? address)
               "proxy-port" (? port-number? port)
               "allow" (or (and #f allow-network) (? list? allow-network))
               "block" (or (and #f block-network) (? list? block-network))
               "cert" (and (or #f (? path-string?)) cert)
               "private" (and (or #f (? path-string?)) private)
               #:closed)])))
(define-match-expander network-pattern
  (lambda (stx)
    (syntax-case stx ()
      [(_ ip mask)
       #'(list (? string? ip) (? string? mask))])))

(module+ test
  (require rackunit)
  (check-match default-config
               (config-pattern _ _ _ _))
  (check-match default-server-config
               (server-config-pattern _ _ _ _ _ _ _))
  (match default-config
    ((config-pattern p ra rp ts)
     (for-each (lambda (t)
                 (check-match t (tunnel-pattern _ _ _ _ _ _ _ _))
                 (match t
                   ((tunnel-pattern nm md da dp la lp an bn)
                    (for-each (lambda (n) (check-match n (network-pattern _ _)))
                              (append (if an an null)
                                      (if bn bn null))))))
               ts)))
  (match default-server-config
    ((server-config-pattern p "127.0.0.1" 9000 a #f #f #f)
     (for-each (lambda (n)
                 (check-match n (network-pattern ip mask)))
               a)))
  )
