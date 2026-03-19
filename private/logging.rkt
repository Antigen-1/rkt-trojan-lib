#lang racket/base
(require racket/logging racket/date racket/contract)
(provide (contract-out (report (-> log-level/c symbol? string? any))))

(define trojan-logger (make-logger))

;; <name> <level>(<date>):
;; <message>
(define (format-message name level msg)
    (parameterize ((date-display-format 'chinese))
        (format "~a ~a(~a):\n~a" name level (date->string (current-date)) msg)))
(define (report level name message)
    (log-message trojan-logger level name (format-message name level message)))
