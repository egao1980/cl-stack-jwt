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

(deftest expired-p-verify-hs
  "expired-p is a predicate even with :verify t (#6); bad signature still signals."
  (let* ((key (ironclad:ascii-string-to-byte-array "secret-key-123456789012345678901234"))
         (tok (encode :hs256 key `(("some" . "old") ("exp" . ,(- (unix-time) 10))))))
    (ok (expired-p tok :verify t :algorithm :hs256 :key key))
    (ng (expired-p tok :verify t :algorithm :hs256 :key key :leeway 60))
    (ok (signals (expired-p tok :verify t :algorithm :hs256
                                :key (ironclad:ascii-string-to-byte-array "wrong-key"))))))

(deftest expired-p-verify-rs256
  (multiple-value-bind (private public)
      (crypto-protocol:generate-key-pair :rsa-pkcs1-sha256)
    (let ((tok (encode :rs256 private `(("sub" . "user") ("exp" . ,(- (unix-time) 10))))))
      (ok (expired-p tok :verify t :algorithm :rs256 :key public))
      (ng (expired-p tok :verify t :algorithm :rs256 :key public :leeway 60))
      (ok (equal "user" (claim tok "sub"))))))

(deftest rs256-roundtrip
  (multiple-value-bind (sk pk)
      (crypto-protocol:generate-key-pair :rsa-pkcs1-sha256)
    (let ((tok (encode :rs256 sk '(("sub" . "rs")))))
      (multiple-value-bind (c h) (decode :rs256 pk tok)
        (ok (equal "rs" (cdr (assoc "sub" c :test #'string=))))
        (ok (equal "RS256" (cdr (assoc "alg" h :test #'string=))))))))

(deftest es256-roundtrip
  (multiple-value-bind (sk pk)
      (crypto-protocol:generate-key-pair :ecdsa-p256-sha256)
    (let ((tok (encode :es256 sk '(("sub" . "es")))))
      (ok (equal "es" (cdr (assoc "sub" (decode :es256 pk tok) :test #'string=)))))))

(deftest eddsa-roundtrip
  (multiple-value-bind (sk pk)
      (crypto-protocol:generate-key-pair :ed25519)
    (let ((tok (encode :eddsa sk '(("sub" . "ed")))))
      (ok (equal "ed" (cdr (assoc "sub" (decode :eddsa pk tok) :test #'string=)))))))
