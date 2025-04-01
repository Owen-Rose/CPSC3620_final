"""
Enhanced Hash Management Module

This module handles hash generation, verification, and comparison
with optimizations for high-performance password cracking.
"""

import hashlib
import hmac
import re
import binascii
from typing import Callable, Dict, List, Set, Optional, Tuple, Union


class HashManager:
    """
    Enhanced hash manager with optimizations for password cracking.
    """
    
    # Map of hash types to their expected lengths (in hex characters)
    HASH_LENGTHS = {
        'md5': 32,
        'sha1': 40,
        'sha256': 64,
    }
    
    # Dictionary mapping hash algorithm names to their implementations
    HASH_FUNCTIONS: Dict[str, Callable[[str], str]] = {
        'md5': lambda password: hashlib.md5(password.encode()).hexdigest(),
        'sha1': lambda password: hashlib.sha1(password.encode()).hexdigest(),
        'sha256': lambda password: hashlib.sha256(password.encode()).hexdigest(),
    }
    
    def __init__(self, hash_type: str, hash_value: str):
        """
        Initialize the hash manager with a specific hash type and target value.
        
        Args:
            hash_type: Type of hash algorithm (e.g., 'md5', 'sha1')
            hash_value: The target hash value to compare against
        
        Raises:
            ValueError: If the hash_type is not supported or hash_value is invalid
        """
        if hash_type not in self.HASH_FUNCTIONS:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        self.hash_type = hash_type
        self.hash_function = self.HASH_FUNCTIONS[hash_type]
        
        # Normalize and validate the hash value
        self.target_hash = self._normalize_hash(hash_value)
        self._validate_hash(self.target_hash)
        
        # Create a binary version of the target hash for faster comparison
        try:
            self.target_hash_bytes = bytes.fromhex(self.target_hash)
        except ValueError:
            # If the hash isn't valid hex, keep it as string only
            self.target_hash_bytes = None
    
    def _normalize_hash(self, hash_value: str) -> str:
        """
        Normalize a hash value by removing whitespace and converting to lowercase.
        
        Args:
            hash_value: The hash value to normalize
            
        Returns:
            Normalized hash value
        """
        # Remove any whitespace and convert to lowercase
        normalized = re.sub(r'\s', '', hash_value).lower()
        
        # Check if this might be a truncated hash and try to fix
        expected_length = self.HASH_LENGTHS.get(self.hash_type)
        if expected_length and len(normalized) < expected_length:
            print(f"[!] Warning: Hash value appears to be truncated. Expected {expected_length} characters, got {len(normalized)}")
            print(f"[*] Adding leading zeros to match expected length")
            # Pad with leading zeros if needed
            normalized = normalized.zfill(expected_length)
        
        return normalized
    
    def _validate_hash(self, hash_value: str) -> None:
        """
        Validate that a hash value is properly formatted.
        
        Args:
            hash_value: The hash value to validate
            
        Raises:
            ValueError: If the hash value is invalid
        """
        # Check if the hash contains only valid hexadecimal characters
        if not all(c in '0123456789abcdef' for c in hash_value):
            raise ValueError(f"Invalid hash value: contains non-hexadecimal characters")
        
        # Check if the hash has the correct length
        expected_length = self.HASH_LENGTHS.get(self.hash_type)
        if expected_length and len(hash_value) != expected_length:
            print(f"[!] Warning: Hash value has unexpected length. Expected {expected_length} characters, got {len(hash_value)}")
    
    def hash_password(self, password: str) -> str:
        """
        Hash a password using the configured hash algorithm.
        
        Args:
            password: The password to hash
            
        Returns:
            The hashed password as a hexadecimal string
        """
        return self.hash_function(password)
    
    def hash_batch(self, passwords: List[str]) -> List[str]:
        """
        Hash multiple passwords at once for better performance.
        
        Args:
            passwords: List of passwords to hash
            
        Returns:
            List of hashed passwords in the same order
        """
        return [self.hash_function(password) for password in passwords]
    
    def verify(self, password: str) -> bool:
        """
        Verify if a password matches the target hash.
        
        Args:
            password: The password to check
            
        Returns:
            True if the password's hash matches the target hash, False otherwise
        """
        # Get the hash of the password
        password_hash = self.hash_password(password)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(password_hash, self.target_hash)
    
    def verify_batch(self, passwords: List[str]) -> List[Tuple[str, bool]]:
        """
        Verify multiple passwords against the target hash.
        
        Args:
            passwords: List of passwords to check
            
        Returns:
            List of tuples (password, match_result)
        """
        results = []
        for password in passwords:
            password_hash = self.hash_password(password)
            match = hmac.compare_digest(password_hash, self.target_hash)
            if match:
                results.append((password, True))
            else:
                results.append((password, False))
        return results
    
    def bulk_verify(self, passwords: List[str]) -> Optional[str]:
        """
        Verify multiple passwords and return the first match if found.
        
        Args:
            passwords: List of passwords to check
            
        Returns:
            The matching password if found, None otherwise
        """
        for password in passwords:
            if self.verify(password):
                return password
        return None
    
    @staticmethod
    def get_supported_algorithms() -> List[str]:
        """
        Get a list of supported hashing algorithms.
        
        Returns:
            List of supported algorithm names
        """
        return list(HashManager.HASH_FUNCTIONS.keys())
    
    @staticmethod
    def detect_hash_type(hash_value: str) -> Optional[str]:
        """
        Attempt to detect the hash type based on the hash value's length and format.
        
        Args:
            hash_value: The hash value to analyze
            
        Returns:
            Detected hash type or None if unknown
        """
        # Normalize the hash
        hash_value = re.sub(r'\s', '', hash_value).lower()
        
        # Check if the hash contains only valid hexadecimal characters
        if not all(c in '0123456789abcdef' for c in hash_value):
            return None
        
        # Check the length of the hash
        hash_length = len(hash_value)
        
        if hash_length == 32:
            return 'md5'
        elif hash_length == 40:
            return 'sha1'
        elif hash_length == 64:
            return 'sha256'
        
        return None