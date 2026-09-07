"""Envelope encryption: standard AEAD, domain KEKs and per-resource DEKs (SystemDesign §34.1).

Only a standard authenticated cipher is used: AES-256-GCM through the maintained
``cryptography`` package. There is no homegrown construction and no plaintext or
cross-domain fallback; a missing provider fails closed with a typed error.
"""
