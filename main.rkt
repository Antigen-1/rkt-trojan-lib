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

(require racket/tcp racket/exn racket/match
         openssl
         "client.rkt" "config.rkt"
         net/ip)

;; Utilities for network sets
(define (pairs->network-set l)
  (map
   (lambda (p)
     (match p
       ((network-pattern ip mask)
        (make-network (make-ip-address ip) (make-ip-address mask)))))
   l))
(define (network-set-member nets addr)
  (and (findf (lambda (net) (network-member net addr))
              nets)
       #t))

;; A trojan2tcp converter
(define (start-tunnel name passwd proxy-address proxy-port dst-address dst-port listen-evt
                      #:sources (ss (ssl-default-verify-sources))
                      #:allow-network-set (as #f)
                      #:reject-network-set (rs #f))
  (define err (current-error-port))
  (define out (current-output-port))
  (let/cc cc
    (let loop ()
      (define (continue) (cc (loop)))
      (call-with-values
       (lambda ()
         (sync listen-evt))
       (lambda (in out)
         ; Check the other end of the connection.
         (define ad (call-with-values (lambda () (tcp-addresses in))
                                      (lambda (_ a) (make-ip-address a))))
         (if (and (or (not as) (network-set-member as ad))
                  (or (not rs) (not (network-set-member rs ad))))
             (void)
             (begin
               (close-input-port in)
               (close-output-port out)
               (displayln (format "~a: A connection from ~a is rejected." name (ip-address->string ad)))
               (continue)))
         (define thd (thread
                      (lambda ()
                        (with-handlers ((exn:fail?
                                         (lambda (e)
                                           (displayln (format "~a: ~a" name (exn->string e)) err))))
                          (parameterize ((ssl-default-verify-sources ss))
                            (start-client passwd
                                          proxy-address proxy-port
                                          dst-address dst-port
                                          in out)
                            (displayln (format "~a: A trojan tunnel is closed." name) out))))))
         (loop))))))

(module+ test
  ;; Any code in this `test` submodule runs when this file is run using DrRacket
  ;; or with `raco test`. The code here does not run when this file is
  ;; required by another module.

  #;(check-equal? (+ 2 2) 4))

(module+ main
  ;; (Optional) main submodule. Put code here if you need it to be executed when
  ;; this file is run using DrRacket or the `racket` executable.  The code here
  ;; does not run when this file is required by another module. Documentation:
  ;; http://docs.racket-lang.org/guide/Module_Syntax.html#%28part._main-and-test%29

  (require racket/cmdline racket/contract racket/system racket/file racket/pretty
           raco/command-name)
  (define certs (box (ssl-default-verify-sources)))
  (define config (box #f))
  (command-line
   #:program (short-program+command-name)
   #:once-each
   [("--config")
    c
    "Read this configuration file if the `start` command is used, or generate a new configuration file if the `new-config` command is used."
    (set-box! config c)]
    #:multi
    [("--cert-dir") c
                    "Add other directories that contain verification sources. Files are automatically rehashed."
                    (if (directory-exists? c)
                        (let ((s (find-executable-path "c_rehash")))
                          (if s
                              (cond ((system* s c))
                                    (else (raise-user-error 'command-line "Fail to run \"c_rehash ~a\"" c)))
                              (let ()
                                (displayln "Cannot find c_rehash executable.")
                                (displayln (format "~a should contain PEM files with hashed symbolic links." c)))))
                        (raise-argument-error 'command-line "directory-exists?" c))
                    (set-box! certs (cons `(directory ,c) (unbox certs)))]
    [("--ignore-certs") "Ignore current verification sources." (set-box! certs null)]
    #:args (command)
    (define/contract config-path
      path-string?
      (unbox config))
    (case command
      (("new-config")
       (call-with-output-file
         config-path
         (lambda (out)
           (pretty-write default-config out))
         #:exists 'error))
      (("start")
       (define/contract cert-list
         (let ([source/c (or/c path-string?
                               (list/c 'directory path-string?)
                               (list/c 'win32-store string?)
                               (list/c 'macosx-keychain (or/c #f path-string?)))])
           (listof source/c))
         (unbox certs))
       (define config-value
         (file->value config-path))
       (match config-value
         ((config-pattern password remote-address remote-port tunnels)
          (define cust (make-custodian (current-custodian)))
          (define out (current-output-port))
          (with-handlers ((exn:break? (lambda (_) (custodian-shutdown-all cust)))
                          (exn:fail? (lambda (e)
                                       (custodian-shutdown-all cust)
                                       (raise e))))
            (parameterize ((current-custodian cust))
              (for-each
               (lambda (t)
                 (match t
                   ((tunnel-pattern name dest-address dest-port local-address local-port allow block)
                    (void (thread
                           (lambda ()
                             (define l (tcp-listen local-port 4 #f local-address))
                             (displayln (format "~a ~a:~a" name local-address local-port) out)
                             (dynamic-wind
                               void
                               (lambda ()
                                 (start-tunnel name password
                                               remote-address remote-port
                                               dest-address dest-port
                                               (handle-evt l tcp-accept)
                                               #:sources cert-list
                                               #:allow-network-set (and allow (pairs->network-set allow))
                                               #:reject-network-set (and block (pairs->network-set block))))
                               (lambda () (tcp-close l)))))))))
                 tunnels)
              (let loop ()
                (sync (handle-evt
                       (alarm-evt (+ (current-milliseconds) 5000))
                       (lambda (_)
                         (collect-garbage 'incremental)
                         (loop)))))
              ))))))
  ))
