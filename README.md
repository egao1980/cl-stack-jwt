# cl-stack-jwt

PyJWT-shaped JWT encode/decode/inspect over [`jose`](https://github.com/fukamachi/jose).

Package: `cl-stack-jwt` (nick `stack-jwt`).

Not an HTTP auth helper — bearer get/refresh/401 → [`cl-stack-oauth2`](https://github.com/egao1980/cl-stack-oauth2).

```lisp
(stack-jwt:encode :hs256 key '(("sub" . "u") ("exp" . 9999999999)))
(stack-jwt:decode :hs256 key token) ; => claims, header
(stack-jwt:inspect-token token)     ; no verify
(stack-jwt:claim token "exp")
(stack-jwt:expired-p token :leeway 60)
```
