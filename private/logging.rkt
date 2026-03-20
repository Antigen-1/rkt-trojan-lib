#lang racket/base
(require racket/logging racket/date racket/contract)
(provide (contract-out (report (-> (or/c symbol? string?) log-level/c string? any))))

(define trojan-logger (make-logger #f (current-logger)))

;; <name> <level>(<date>):
;; <message>
(define (format-message name level msg)
    (parameterize ((date-display-format 'chinese))
        (format "~a ~a(~a):\n~a" name level (date->string (current-date)) msg)))
(define (report name level message)
    (log-message trojan-logger level (if (symbol? name) name (string->symbol name)) (format-message name level message)))

(module+ test
    (require rackunit racket/match)
    (define recver (make-log-receiver trojan-logger 'info))
    (report 'Test 'info "test-logging")
    (check-match (sync recver)
        (vector 'info (and (regexp "Test") (regexp "test-logging")) #f 'Test)))