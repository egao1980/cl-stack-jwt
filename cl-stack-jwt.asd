(defsystem "cl-stack-jwt"
  :version "0.3.1"
  :description "JWT encode/decode/inspect — HS*/RS256/PS256/ES256/EdDSA via crypto-protocol"
  :author "egao1980"
  :license "MIT"
  :depends-on ("crypto-protocol" "secrets-protocol" "babel" "yason" "encoding-protocol")
:serial t
  :pathname "src"
  :components ((:file "package")
               (:file "jwt"))
  :in-order-to ((test-op (test-op "cl-stack-jwt/tests"))))

(defsystem "cl-stack-jwt/tests"
  :depends-on ("cl-stack-jwt" "crypto-backend-ironclad" "rove" "ironclad")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "jwt-test"))
  :perform (test-op (o c)
             (unless (symbol-call :rove :run c)
               (error "tests failed for ~A" (component-name c)))))
