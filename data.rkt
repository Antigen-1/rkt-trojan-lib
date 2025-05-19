#lang racket/base
(require racket/contract racket/tcp net/ip)
(provide (contract-out
          (struct client-data ((passwd string?)
                               (request request?)
                               (payload input-port?)))
          ;; Currently UDP is not supported
          (struct request ((command (or/c 'connect 'udp-associate))
                           (address-type (or/c 'ipv4 'domain 'ipv6))
                           (address (or/c string? ip-address?))
                           (port port-number?)))))

(struct client-data (passwd request payload))
(struct request (command address-type address port))
