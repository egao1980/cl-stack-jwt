(in-package #:cl-stack-jwt)

;;; Thin PyJWT-shaped facade over fukamachi/jose.
;;; Not an HTTP auth helper — use cl-stack-oauth2 for bearer token flows.

(defconstant +unix-universal-offset+ 2208988800
  "Seconds between CL universal-time epoch (1900) and Unix epoch (1970).")

(defun universal-time->unix (ut)
  (- ut +unix-universal-offset+))

(defun unix->universal-time (unix)
  (+ unix +unix-universal-offset+))

(defun unix-time ()
  (universal-time->unix (get-universal-time)))

(defun encode (algorithm key claims &key headers)
  "Sign CLAIMS (alist) with ALGORITHM/KEY → compact JWT string."
  (jose:encode algorithm key claims :headers headers))

(defun decode (algorithm key token)
  "Verify and decode TOKEN → (values claims-alist header-alist)."
  (jose:decode algorithm key token))

(defun inspect-token (token)
  "Decode without verify → (values claims header signature-octets)."
  (jose:inspect-token token))

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
  "T if `exp` present and NOW >= exp + LEEWAY (Unix seconds; LEEWAY = clock skew grace)."
  (let ((exp (claim token "exp" :verify verify :algorithm algorithm :key key)))
    (and (numberp exp)
         (>= now (+ exp leeway)))))
