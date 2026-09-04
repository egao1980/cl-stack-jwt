#!/usr/bin/env python3
"""PyJWT interop helper. stdin: JSON {op, alg, token?, claims?, key_pem?}."""

from __future__ import annotations

import json
import sys

import jwt
from jwt.algorithms import ECAlgorithm, Ed25519Algorithm, RSAAlgorithm


def main() -> None:
    req = json.load(sys.stdin)
    op = req["op"]
    alg = req["alg"]
    if op == "decode":
        key = _load_key(alg, req["key_pem"], private=False)
        claims = jwt.decode(req["token"], key=key, algorithms=[alg])
        print(json.dumps({"claims": claims}))
        return
    if op == "encode":
        key = _load_key(alg, req["key_pem"], private=True)
        token = jwt.encode(req["claims"], key=key, algorithm=alg)
        print(json.dumps({"token": token}))
        return
    raise SystemExit(f"unknown op {op}")


def _load_key(alg: str, pem: str, *, private: bool):
    raw = pem.encode()
    if alg in {"RS256", "PS256"}:
        return RSAAlgorithm.from_pem(raw)
    if alg == "ES256":
        return ECAlgorithm.from_pem(raw)
    if alg == "EdDSA":
        return Ed25519Algorithm.from_pem(raw)
    raise SystemExit(f"unsupported alg {alg}")


if __name__ == "__main__":
    main()
