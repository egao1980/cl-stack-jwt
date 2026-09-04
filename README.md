# cl-stack-jwt

PyJWT-shaped JWT encode/decode/inspect.

- **HS256 / HS384 / HS512** → [`crypto-protocol:hmac`](https://github.com/egao1980/crypto-protocol)
- **RS256 / PS256 / ES256 / EdDSA** → [`crypto-protocol:sign`](https://github.com/egao1980/crypto-protocol) / `verify`

Package: `cl-stack-jwt` (nick `stack-jwt`). **OCI: 0.3.0.**

Not an HTTP auth helper — bearer get/refresh/401 →
[`cl-stack-oauth2`](https://github.com/egao1980/cl-stack-oauth2).

## Install

```lisp
(cl-repo:load-system "crypto-backend-ironclad" :version "0.2.0")
(cl-repo:load-system "cl-stack-jwt" :version "0.3.0")
```

## Usage

```lisp
(defvar *key* (babel:string-to-octets "secret-key-123456" :encoding :utf-8))

(stack-jwt:encode :hs256 *key* '(("sub" . "u") ("exp" . 9999999999)))
(stack-jwt:decode :hs256 *key* token) ; => claims, header
(stack-jwt:inspect-token token)       ; no verify → claims, header, sig
(stack-jwt:claim token "exp")
(stack-jwt:expired-p token :leeway 60)
```

## License

MIT
