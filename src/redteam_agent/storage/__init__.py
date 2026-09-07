"""SQLite repositories with write/read integrity (SystemDesign §32, B-06/H-03).

Every security artifact with an object-integrity digest is verified both when it
is written and when it is read back, so tampering or a wrong binding fails
closed rather than being trusted.
"""
