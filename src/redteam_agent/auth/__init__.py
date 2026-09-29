"""Operator authentication and RBAC boundary (SystemDesign §2.6).

Phase 0A wires a Root-fixed authentication test double and a per-mission role
assignment store. A caller-supplied id or role string is never trusted as
authority; approval authority is derived from an authenticated principal that
holds the approver role assigned to *that* mission. Production sockets/UI are a
later phase; only the boundary and protocol exist here.
"""
