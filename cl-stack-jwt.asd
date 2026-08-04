(defsystem "cl-stack-jwt"
  :version "0.1.0"
  :description "JWT encode/decode/inspect facade over jose (PyJWT-shaped)"
  :author "egao1980"
  :license "MIT"
  :depends-on ("jose" "alexandria")
  :serial t
  :pathname "src"
  :components ((:file "package")
               (:file "jwt"))
  :in-order-to ((test-op (test-op "cl-stack-jwt/tests"))))

(defsystem "cl-stack-jwt/tests"
  :depends-on ("cl-stack-jwt" "rove" "ironclad")
  :pathname "tests"
  :serial t
  :components ((:file "package")
               (:file "jwt-test"))
  :perform (test-op (o c)
             (symbol-call :rove :run c)))
