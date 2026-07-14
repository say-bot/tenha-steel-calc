#!/usr/bin/env python3
"""index.html(암호 게이트) → source.html(평문) 복원. encrypt.py의 역연산.
사용법:  CHEONHA_PW='암호' python decrypt.py [index.html] [source.html]
"""
import os, sys, base64, json, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SRC = sys.argv[1] if len(sys.argv) > 1 else "index.html"
OUT = sys.argv[2] if len(sys.argv) > 2 else "source.html"
pw = os.environ.get("CHEONHA_PW")
if not pw:
    sys.exit("환경변수 CHEONHA_PW 에 암호를 넣어주세요.")

html = open(SRC, encoding="utf-8").read()
m = re.search(r'<script id="payload"[^>]*>(.*?)</script>', html, re.S)
if not m:
    sys.exit("payload 스크립트를 찾지 못함 — 이미 평문이거나 형식이 다릅니다.")
P = json.loads(m.group(1))
b64d = lambda s: base64.b64decode(s)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b64d(P["salt"]),
                 iterations=P["it"]).derive(pw.encode("utf-8"))
try:
    full = AESGCM(key).decrypt(b64d(P["iv"]), b64d(P["ct"]), None).decode("utf-8")
except Exception:
    sys.exit("복호화 실패 — 암호가 올바르지 않습니다.")
open(OUT, "w", encoding="utf-8").write(full)
print(f"OK  {SRC} -> {OUT}  ({len(full):,} bytes)")
