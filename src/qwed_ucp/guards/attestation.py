"""Attestation Guard - JWT signing for verified UCP checkouts.

Generates cryptographic proofs (JWTs) for verification results.
Acts as a 'Digital Notary' for UCP commerce verification.

Part of QWED-UCP Deterministic Verification Engine.
Based on: qwed-verification/qwed/guards/attestation_guard.py
"""

import jwt
import time
import json
import hashlib
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class AttestationResult:
    """Result from attestation signing."""
    
    token: Optional[str] = None
    verified: bool = False
    error: Optional[str] = None
    details: dict = field(default_factory=dict)
    engine: str = "QWED-Deterministic-v1"
    verification_mode: str = "deterministic"


class AttestationGuard:
    """
    Generates cryptographic proofs (JWTs) for UCP verification results.
    
    Creates tamper-proof tokens that attest:
    - A checkout was verified at a specific time
    - The verification result (pass/fail)
    - Which guards ran and their outcomes
    """
    
    def __init__(self, secret_key: str = None, allow_insecure: bool = False):
        """
        Initialize AttestationGuard.
        
        Args:
            secret_key: Secret key for JWT signing (or set QWED_ATTESTATION_SECRET)
            allow_insecure: Allow dev mode with insecure default secret
        """
        self.secret = secret_key or os.environ.get("QWED_ATTESTATION_SECRET")
        if not self.secret:
            if allow_insecure or os.environ.get("QWED_DEV_MODE") == "1":
                # deepcode ignore HardcodedSecret: Dev-mode fallback, only active with explicit opt-in
                self.secret = "dev-secret-insecure"
            else:
                raise ValueError("QWED_ATTESTATION_SECRET required. Set allow_insecure=True for dev mode.")
    
    def sign_checkout(
        self,
        checkout: Dict[str, Any],
        verification_result: Dict[str, Any],
        guards_passed: list = None
    ) -> AttestationResult:
        """
        Create a JWT attesting that a checkout was verified.
        
        Args:
            checkout: The UCP checkout object
            verification_result: Result from UCPVerifier.verify_checkout()
            guards_passed: List of guards that passed (optional)
            
        Returns:
            AttestationResult with signed JWT token
        """
        try:
            # Create hash of checkout to link attestation without storing PII
            checkout_hash = hashlib.sha256(
                json.dumps(checkout, sort_keys=True).encode('utf-8')
            ).hexdigest()
            
            payload = {
                "iss": "qwed-ucp-attestation",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,  # 1 hour expiry
                "checkout_hash": checkout_hash,
                "verified": verification_result.get("verified", False),
                "guards_passed": guards_passed or [],
                "errors": verification_result.get("errors", []),
                "engine": "QWED-Deterministic-v1",
                "verification_mode": "deterministic"
            }
            
            token = jwt.encode(payload, self.secret, algorithm="HS256")
            
            return AttestationResult(
                token=token,
                verified=True,
                details={
                    "checkout_hash": checkout_hash,
                    "issued_at": payload["iat"],
                    "expires_at": payload["exp"]
                }
            )
        except Exception as e:
            return AttestationResult(
                verified=False,
                error=f"Failed to create attestation: {str(e)}"
            )
    
    def verify_attestation(self, token: str) -> AttestationResult:
        """
        Verify a QWED-UCP attestation token.
        
        Args:
            token: JWT token to verify
            
        Returns:
            AttestationResult with decoded payload
        """
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
            return AttestationResult(
                token=token,
                verified=True,
                details=payload
            )
        except jwt.ExpiredSignatureError:
            return AttestationResult(
                verified=False,
                error="Attestation token expired"
            )
        except jwt.InvalidTokenError as e:
            return AttestationResult(
                verified=False,
                error=f"Invalid attestation: {str(e)}"
            )
    
    def create_receipt(
        self,
        checkout: Dict[str, Any],
        verification_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a verification receipt (non-cryptographic summary).
        
        Args:
            checkout: The UCP checkout object
            verification_result: Result from verification
            
        Returns:
            Receipt dictionary
        """
        checkout_hash = hashlib.sha256(
            json.dumps(checkout, sort_keys=True).encode('utf-8')
        ).hexdigest()[:16]  # Short hash for receipt
        
        return {
            "receipt_id": f"QWED-{checkout_hash.upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verified": verification_result.get("verified", False),
            "engine": "QWED-Deterministic-v1",
            "verification_mode": "deterministic",
            "errors": verification_result.get("errors", [])
        }
