"""Context selection, index and read-authorization grant models.

The context selector reads only index metadata, never resource bodies or
secrets (safety-invariants). Read authorization is a distinct grant owned by the
context authorization path, separate from execution authorization.
"""
