(in-package #:cl-stack-jwt)

;;; PyJWT-shaped facade.
;;; HS256/384/512 → crypto-protocol:hmac (+ secrets constant-time compare).
;;; Other algorithms → jose (RSA/ECDSA/etc).

(defconstant +unix-universal-offset+ 2208988800
  "Seconds between CL universal-time epoch (1900) and Unix epoch (1970).")

(defun universal-time->unix (ut)
  (- ut +unix-universal-offset+))

(defun unix->universal-time (unix)
  (+ unix +unix-universal-offset+))

(defun unix-time ()
  (universal-time->unix (get-universal-time)))

(defun %b64url-encode (octets)
  (string-right-trim
   '(#\=)
   (map 'string
        (lambda (c)
          (case c
            (#\+ #\-)
            (#\/ #\_)
            (t c)))
        (cl-base64:usb8-array-to-base64-string octets))))

(defun %b64url-decode (string)
  (let* ((s (map 'string
                 (lambda (c)
                   (case c
                     (#\- #\+)
                     (#\_ #\/)
                     (t c)))
                 string))
         (pad (case (mod (length s) 4)
                (2 "==")
                (3 "=")
                (t ""))))
    (cl-base64:base64-string-to-usb8-array (concatenate 'string s pad))))

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

(defun %key-octets (key)
  (etypecase key
    ((vector (unsigned-byte 8)) key)
    (string (babel:string-to-octets key :encoding :utf-8))))

(defun %alist-to-hash (alist)
  (let ((h (make-hash-table :test 'equal)))
    (dolist (pair alist h)
      (setf (gethash (car pair) h) (cdr pair)))))

(defun %encode-hs (algorithm key claims headers)
  (let* ((alg (%hmac-alg-name algorithm))
         (hdr (%alist-to-hash
               (append `(("alg" . ,alg) ("typ" . "JWT")) headers)))
         (payload (%alist-to-hash claims))
         (h64 (%b64url-encode (babel:string-to-octets (%json-encode hdr) :encoding :utf-8)))
         (p64 (%b64url-encode (babel:string-to-octets (%json-encode payload) :encoding :utf-8)))
         (signing-input (format nil "~a.~a" h64 p64))
         (sig (crypto-protocol:hmac (%key-octets key)
                                    (babel:string-to-octets signing-input :encoding :utf-8)
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
                      (babel:string-to-octets signing-input :encoding :utf-8)
                      :algorithm (%hmac-digest algorithm)))
           (got (%b64url-decode s64)))
      (unless (secrets-protocol:constant-time-equal expected got)
        (error "JWT signature mismatch"))
      (values (%json-decode (babel:octets-to-string (%b64url-decode p64) :encoding :utf-8))
              (%json-decode (babel:octets-to-string (%b64url-decode h64) :encoding :utf-8))))))

(defun encode (algorithm key claims &key headers)
  "Sign CLAIMS (alist) with ALGORITHM/KEY → compact JWT string."
  (if (%hmac-p algorithm)
      (%encode-hs algorithm key claims headers)
      (jose:encode algorithm key claims :headers headers)))

(defun decode (algorithm key token)
  "Verify and decode TOKEN → (values claims-alist header-alist)."
  (if (%hmac-p algorithm)
      (%decode-hs algorithm key token)
      (jose:decode algorithm key token)))

(defun inspect-token (token)
  "Decode without verify → (values claims header signature-octets)."
  (multiple-value-bind (h64 p64 s64) (%split-token token)
    (values (%json-decode (babel:octets-to-string (%b64url-decode p64) :encoding :utf-8))
            (%json-decode (babel:octets-to-string (%b64url-decode h64) :encoding :utf-8))
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

   With VERIFY T the signature is still checked (signature errors signal), but
   jose's own time-claim checks are continued so this predicate — including
   LEEWAY — stays authoritative for the expiration answer."
  (let ((exp (if verify
                 ;; jose:decode CERRORs on exp/nbf before we can inspect them;
                 ;; invoke its continue restart and decide from the claim.
                 (handler-bind ((jose/errors:jwt-claims-expired #'continue)
                                (jose/errors:jwt-claims-not-yet-valid #'continue))
                   (claim token "exp" :verify t :algorithm algorithm :key key))
                 (claim token "exp"))))
    (and (numberp exp)
         (>= now (+ exp leeway)))))
