#lang info
(define collection "rkt-trojan-lib")
(define deps '("base" "net-ip-lib"))
(define build-deps '("scribble-lib" "racket-doc" "rackunit-lib"))
(define scribblings '(("scribblings/rkt-trojan-lib.scrbl" ())))
(define pkg-desc "Description Here")
;; Features; Bug Fixes; Improvements
(define version "4.0.0")
(define pkg-authors '(zhanghao))
(define license '(Apache-2.0 OR MIT))
(define raco-commands (list (list "tunnel" '(submod rkt-trojan-lib main) "My trojan2tcp converter" #f)))
