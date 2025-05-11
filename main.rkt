#lang racket/base

(module+ test
  (require rackunit))

;; Notice
;; To install (from within the package directory):
;;   $ raco pkg install
;; To install (once uploaded to pkgs.racket-lang.org):
;;   $ raco pkg install <<name>>
;; To uninstall:
;;   $ raco pkg remove <<name>>
;; To view documentation:
;;   $ raco docs <<name>>
;;
;; For your convenience, we have included LICENSE-MIT and LICENSE-APACHE files.
;; If you would prefer to use a different license, replace those files with the
;; desired license.
;;
;; Some users like to add a `private/` directory, place auxiliary files there,
;; and require them in `main.rkt`.
;;
;; See the current version of the racket style guide here:
;; http://docs.racket-lang.org/style/index.html

;; Code here

(require racket/tcp racket/exn "client.rkt" openssl)

(define (make-custom-client-context private-key-path)
  (let ((ctx (ssl-make-client-context
              'auto
              #:private-key (list 'pem private-key-path))))
    ; Certificate and hostname verification are disabled
    (ssl-set-verify! ctx #f)
    (ssl-set-verify-hostname! ctx #f)
    ; No weak cipher suites
    (ssl-set-ciphers! ctx "DEFAULT:!aNULL:!eNULL:!LOW:!EXPORT:!SSLv2")
    ; Seal context so further changes cannot weaken it
    (ssl-seal-context! ctx)
    ctx))

;; A trojan2tcp converter
(define (start-tunnel passwd proxy-address proxy-port dst-address dst-port local-port
                      #:context (ctx 'secure))
  (with-handlers ((exn:break? (lambda (_)
                                (custodian-shutdown-all (current-custodian))
                                (void))))
    (define l (tcp-listen local-port))
    (let loop ()
      (call-with-values
       (lambda ()
         (sync (handle-evt l tcp-accept)))
       (lambda (in out)
         (define thd (thread
                      (lambda ()
                        (define cust (make-custodian (current-custodian)))
                        (with-handlers ((exn:fail?
                                         (lambda (e)
                                           (custodian-shutdown-all cust)
                                           (displayln (exn->string e) (current-error-port)))))
                          (parameterize ((current-custodian cust))
                            (start-client passwd
                                          proxy-address proxy-port
                                          dst-address dst-port
                                          in out
                                          #:context ctx))))))
         (loop))))))

(module+ test
  ;; Any code in this `test` submodule runs when this file is run using DrRacket
  ;; or with `raco test`. The code here does not run when this file is
  ;; required by another module.

  (check-equal? (+ 2 2) 4))

(module+ main
  ;; (Optional) main submodule. Put code here if you need it to be executed when
  ;; this file is run using DrRacket or the `racket` executable.  The code here
  ;; does not run when this file is required by another module. Documentation:
  ;; http://docs.racket-lang.org/guide/Module_Syntax.html#%28part._main-and-test%29

  (require racket/cmdline racket/contract raco/command-name)
  (define passwd (box #f))
  (define proxy-address (box #f))
  (define proxy-port (box #f))
  (define dst-address (box #f))
  (define dst-port (box #f))
  (define local-port (box #f))
  (define key-path (box #f))
  (command-line
    #:program (short-program+command-name)
    #:once-each
    [("-p" "--passwd") p "The password used for verification." (set-box! passwd p)]
    [("--proxy-address") a "The address of the proxy server." (set-box! proxy-address a)]
    [("--proxy-port") p "The tcp port of the proxy server." (set-box! proxy-port (string->number p))]
    [("--dst-address") a "The address of the destination server." (set-box! dst-address a)]
    [("--dst-port") p "The tcp port of the destination server." (set-box! dst-port (string->number p))]
    [("--local-port") p "The tcp port that this client listens to." (set-box! local-port (string->number p))]
    [("--custom-private-key") p "Use the custom private key instead." (set-box! key-path p)]
    #:args ()
    (define/contract passwd-value string? (unbox passwd))
    (define/contract proxy-address-value string? (unbox proxy-address))
    (define/contract proxy-port-value port-number? (unbox proxy-port))
    (define/contract dst-address-value string? (unbox dst-address))
    (define/contract dst-port-value port-number? (unbox dst-port))
    (define/contract local-port-value port-number? (unbox local-port))
    (define/contract key-path-value (or/c #f (and/c path-string? file-exists?)) (unbox key-path))
    (start-tunnel passwd-value
                  proxy-address-value proxy-port-value
                  dst-address-value dst-port-value
                  local-port-value
                  #:context (if key-path-value
                                (make-custom-client-context key-path-value)
                                'secure))
    ))
