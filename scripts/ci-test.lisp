(setf *debugger-hook*
      (lambda (c h)
        (declare (ignore h))
        (format *error-output* "~&UNHANDLED: ~A~%" c)
        (uiop:quit 1)))

(setf asdf:*compile-file-failure-behaviour* :warn)

(defun call-with-ci-muffles (fn)
  #+sbcl
  (handler-bind ((sb-ext:defconstant-uneql
                  (lambda (c)
                    (declare (ignore c))
                    (let ((r (find-restart 'continue)))
                      (when r (invoke-restart r))))))
    (funcall fn))
  #-sbcl
  (funcall fn))

(call-with-ci-muffles (lambda () (asdf:load-system "cl-repository-client")))
(cl-repository-client/asdf-integration:configure-asdf-source-registry)
(cl-repository-client/asdf-integration:load-system-init-files)

(call-with-ci-muffles
 (lambda ()
   (dolist (n '("crypto-protocol" "secrets-protocol" "crypto-backend-ironclad"
                "cl-stack-jwt" "jose" "babel" "yason" "cl-base64" "alexandria"
                "ironclad" "uuid" "rove"))
     (unless (asdf:find-system n nil)
       (ql:quickload n :silent t)))
   (asdf:test-system "cl-stack-jwt")))

(uiop:quit 0)
