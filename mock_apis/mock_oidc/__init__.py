"""Mock OIDC identity provider — DEV ONLY, DO NOT USE IN PRODUCTION.

This package exposes a FastAPI app that mimics the minimal OIDC surface the
auth gateway depends on: a discovery document, a JWKS endpoint, a token
endpoint, and a developer shortcut (``GET /login?email=...``) that mints a
signed token without requiring a browser flow.

The signing key is generated in-memory on startup and never persisted.
Do not point any production system at this module.
"""
