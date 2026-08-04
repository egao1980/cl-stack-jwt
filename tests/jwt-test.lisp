(in-package #:cl-stack-jwt/tests)

(deftest hs256-roundtrip
  (let* ((key (ironclad:ascii-string-to-byte-array "secret-key-123456"))
         (claims `(("sub" . "user") ("exp" . ,(+ (unix-time) 3600))))
         (tok (encode :hs256 key claims)))
    (ok (stringp tok))
    (multiple-value-bind (c h) (decode :hs256 key tok)
      (ok (equal "user" (cdr (assoc "sub" c :test #'string=))))
      (ok (equal "HS256" (cdr (assoc "alg" h :test #'string=)))))
    (ok (equal "user" (claim tok "sub")))
    (ng (expired-p tok))))

(deftest inspect-unverified
  (let* ((key (ironclad:ascii-string-to-byte-array "k"))
         (tok (encode :hs256 key '(("hello" . "world")))))
    (ok (equal "world" (claim tok "hello")))
    (ok (equal "world" (cdr (assoc "hello" (claims tok) :test #'string=))))))

(deftest expired-claim
  (let* ((key (ironclad:ascii-string-to-byte-array "k"))
         (tok (encode :hs256 key `(("exp" . ,(- (unix-time) 10))))))
    (ok (expired-p tok))
    (ng (expired-p tok :leeway 60))))
