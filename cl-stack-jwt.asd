(defsystem "cl-stack-jwt"
  :version "0.2.0"
  :description "JWT encode/decode/inspect — HS* via crypto-protocol:hmac (jose for other algs)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("crypto-protocol" "secrets-protocol" "babel" "yason" "cl-base64" "alexandria" "jose")

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
