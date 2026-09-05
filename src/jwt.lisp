(in-package #:cl-stack-jwt)

;;; PyJWT-shaped facade.
;;; HS* → crypto-protocol:hmac. RS256/PS256/ES256/EdDSA → crypto-protocol:sign.

(defconstant +unix-universal-offset+ 2208988800
  "Seconds between CL universal-time epoch (1900) and Unix epoch (1970).")

(defun universal-time->unix (ut)
  (- ut +unix-universal-offset+))

(defun unix->universal-time (unix)
  (+ unix +unix-universal-offset+))

(defun unix-time ()
  (universal-time->unix (get-universal-time)))

(defun %b64url-encode (octets)
  (encoding-protocol:encode octets :encoding :base64url :pad nil))

(defun %b64url-decode (string)
  (encoding-protocol:decode string :encoding :base64url :pad nil))

(defun %json-encode (obj)
  (with-output-to-string (out)
    (yason:encode obj out)))

(defun %json-decode (string)
  (yason:parse string :object-as :alist :json-arrays-as-vectors t))

(defun %hmac-digest (algorithm)
  (ecase algorithm
    ((:hs256 :HS256) :sha256)
    ((:hs384 :HS384) :sha384)
    ((:hs512 :HS512) :sha512)))

(defun %hmac-alg-name (algorithm)
  (ecase algorithm
    ((:hs256 :HS256) "HS256")
    ((:hs384 :HS384) "HS384")
    ((:hs512 :HS512) "HS512")))

(defun %hmac-p (algorithm)
  (member algorithm '(:hs256 :HS256 :hs384 :HS384 :hs512 :HS512)))

(defun %crypto-sig-alg (algorithm)
  "Map JWT alg → crypto-protocol signature keyword, or NIL."
  (cond
    ((member algorithm '(:rs256 :RS256)) :rsa-pkcs1-sha256)
    ((member algorithm '(:ps256 :PS256)) :rsa-pss-sha256)
    ((member algorithm '(:es256 :ES256)) :ecdsa-p256-sha256)
    ((member algorithm '(:eddsa :EdDSA :ed25519 :ED25519)) :ed25519)
    (t nil)))

(defun %jwt-alg-name (algorithm)
  (cond
    ((%hmac-p algorithm) (%hmac-alg-name algorithm))
    ((member algorithm '(:rs256 :RS256)) "RS256")
    ((member algorithm '(:ps256 :PS256)) "PS256")
    ((member algorithm '(:es256 :ES256)) "ES256")
    ((member algorithm '(:eddsa :EdDSA :ed25519 :ED25519)) "EdDSA")
    (t (string-upcase (string algorithm)))))

(defun %key-octets (key)
  (etypecase key
    ((vector (unsigned-byte 8)) key)
    (string (encoding-protocol:encode key))))

(defun %alist-to-hash (alist)
  (let ((h (make-hash-table :test 'equal)))
    (dolist (pair alist h)
      (setf (gethash (car pair) h) (cdr pair)))))

(defun %encode-hs (algorithm key claims headers)
  (let* ((alg (%hmac-alg-name algorithm))
         (hdr (%alist-to-hash
               (append `(("alg" . ,alg) ("typ" . "JWT")) headers)))
         (payload (%alist-to-hash claims))
         (h64 (%b64url-encode (encoding-protocol:encode (%json-encode hdr))))
         (p64 (%b64url-encode (encoding-protocol:encode (%json-encode payload))))
         (signing-input (format nil "~a.~a" h64 p64))
         (sig (crypto-protocol:hmac (%key-octets key)
                                    (encoding-protocol:encode signing-input)
                                    :algorithm (%hmac-digest algorithm))))
    (format nil "~a.~a" signing-input (%b64url-encode sig))))

(defun %split-token (token)
  (let ((parts (uiop:split-string token :separator '(#\.))))
    (unless (= (length parts) 3)
      (error "invalid JWT: expected 3 segments"))
    (values (first parts) (second parts) (third parts))))

(defun %decode-hs (algorithm key token)
  (multiple-value-bind (h64 p64 s64) (%split-token token)
    (let* ((signing-input (format nil "~a.~a" h64 p64))
           (expected (crypto-protocol:hmac
                      (%key-octets key)
                      (encoding-protocol:encode signing-input)
                      :algorithm (%hmac-digest algorithm)))
           (got (%b64url-decode s64)))
      (unless (secrets-protocol:constant-time-equal expected got)
        (error "JWT signature mismatch"))
      (values (%json-decode (encoding-protocol:decode (%b64url-decode p64)))
              (%json-decode (encoding-protocol:decode (%b64url-decode h64)))))))

(defun %encode-crypto (crypto-alg jwt-alg key claims headers)
  (let* ((alg (%jwt-alg-name jwt-alg))
         (hdr (%alist-to-hash
               (append `(("alg" . ,alg) ("typ" . "JWT")) headers)))
         (payload (%alist-to-hash claims))
         (h64 (%b64url-encode (encoding-protocol:encode (%json-encode hdr))))
         (p64 (%b64url-encode (encoding-protocol:encode (%json-encode payload))))
         (signing-input (format nil "~a.~a" h64 p64))
         (sig (crypto-protocol:sign
               (encoding-protocol:encode signing-input)
               :algorithm crypto-alg :key key)))
    (format nil "~a.~a" signing-input (%b64url-encode sig))))

(defun %decode-crypto (crypto-alg key token)
  (multiple-value-bind (h64 p64 s64) (%split-token token)
    (let ((signing-input (format nil "~a.~a" h64 p64))
          (got (%b64url-decode s64)))
      (crypto-protocol:verify
       (encoding-protocol:encode signing-input)
       got :algorithm crypto-alg :key key)
      (values (%json-decode (encoding-protocol:decode (%b64url-decode p64)))
              (%json-decode (encoding-protocol:decode (%b64url-decode h64)))))))

(defun %unsupported-algorithm (algorithm)
  (error "unsupported JWT algorithm ~S (HS256/384/512, RS256, PS256, ES256, EdDSA)"
         algorithm))

(defun encode (algorithm key claims &key headers)
  "Sign CLAIMS (alist) with ALGORITHM/KEY → compact JWT string."
  (cond
    ((%hmac-p algorithm)
     (%encode-hs algorithm key claims headers))
    ((%crypto-sig-alg algorithm)
     (%encode-crypto (%crypto-sig-alg algorithm) algorithm key claims headers))
    (t
     (%unsupported-algorithm algorithm))))

(defun decode (algorithm key token)
  "Verify and decode TOKEN → (values claims-alist header-alist)."
  (cond
    ((%hmac-p algorithm)
     (%decode-hs algorithm key token))
    ((%crypto-sig-alg algorithm)
     (%decode-crypto (%crypto-sig-alg algorithm) key token))
    (t
     (%unsupported-algorithm algorithm))))

(defun inspect-token (token)
  "Decode without verify → (values claims header signature-octets)."
  (multiple-value-bind (h64 p64 s64) (%split-token token)
    (values (%json-decode (encoding-protocol:decode (%b64url-decode p64)))
            (%json-decode (encoding-protocol:decode (%b64url-decode h64)))
            (%b64url-decode s64))))

(defun claims (token &key verify algorithm key)
  "Return claims alist. VERIFY T requires ALGORITHM and KEY."
  (if verify
      (decode algorithm key token)
      (nth-value 0 (inspect-token token))))

(defun header (token &key verify algorithm key)
  (if verify
      (nth-value 1 (decode algorithm key token))
      (nth-value 1 (inspect-token token))))

(defun %aget (alist key)
  (or (cdr (assoc key alist :test #'string=))
      (cdr (assoc key alist :test #'equalp))
      (cdr (assoc (intern (string-upcase key) :keyword) alist))))

(defun claim (token claim-name &key verify algorithm key)
  "Return single claim (string name) from TOKEN, or NIL."
  (%aget (claims token :verify verify :algorithm algorithm :key key)
         claim-name))

(defun expired-p (token &key (leeway 0) verify algorithm key
                          (now (unix-time)))
  "T if `exp` present and NOW >= exp + LEEWAY (Unix seconds; LEEWAY = clock skew grace).
   VERIFY T still checks the signature (mismatch signals); exp itself is this predicate."
  (let ((exp (if verify
                 (claim token "exp" :verify t :algorithm algorithm :key key)
                 (claim token "exp"))))
    (and (numberp exp)
         (>= now (+ exp leeway)))))
