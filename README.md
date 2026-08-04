# cl-stack-jwt

PyJWT-shaped JWT encode/decode/inspect over [`jose`](https://github.com/fukamachi/jose)
(imported via [`cl-stack-systems`](https://github.com/egao1980/cl-stack-systems) →
`ghcr.io/egao1980/cl-systems/jose:0.1.0`).

Package: `cl-stack-jwt` (nick `stack-jwt`). **OCI: 0.1.0.**

Not an HTTP auth helper — bearer get/refresh/401 →
[`cl-stack-oauth2`](https://github.com/egao1980/cl-stack-oauth2).

## Install

```lisp
(cl-repo:load-system "cl-stack-jwt" :version "0.1.0")
;; jose comes from OCI; ironclad / cl-json / assoc-utils / trivial-utf-8 may
;; QL-fallback until those are also imported into cl-stack-systems.
```

OCI: `ghcr.io/egao1980/cl-systems/cl-stack-jwt:0.1.0`

## Usage

```lisp
(defvar *key* (ironclad:ascii-string-to-byte-array "secret-key-123456"))

(stack-jwt:encode :hs256 *key* '(("sub" . "u") ("exp" . 9999999999)))
(stack-jwt:decode :hs256 *key* token) ; => claims, header
(stack-jwt:inspect-token token)       ; no verify → claims, header, sig
(stack-jwt:claim token "exp")
(stack-jwt:claims token)
(stack-jwt:header token)
(stack-jwt:expired-p token :leeway 60)

(stack-jwt:unix-time)
(stack-jwt:unix->universal-time exp)
(stack-jwt:universal-time->unix ut)
```

Algorithms: whatever `jose` supports (HS256/384/512, RS*, PS*, none).

## License

MIT
