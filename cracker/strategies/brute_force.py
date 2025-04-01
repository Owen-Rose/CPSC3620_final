"""
Brute Force Attack Strategy Module

This module implements a targeted brute force attack using Breadth-First Search
(BFS) to efficiently search the password space level by level.
"""

import time
import string
import threading
from collections import deque
from typing import Dict, Any, List, Set, Optional, Iterator

from tqdm import tqdm

from cracker.strategies.base import BaseStrategy, CrackingResult
from cracker.hash_manager import HashManager


class BruteForceAttack(BaseStrategy):
    """
    Targeted brute force attack strategy using BFS to ensure shorter passwords
    are tried before longer ones, with priority based on character probability.
    """
    
    def __init__(self, hash_manager: HashManager, config: Dict[str, Any]):
        """
        Initialize the brute force attack strategy.
        
        Args:
            hash_manager: The hash manager for verification
            config: Configuration parameters
        """
        super().__init__(hash_manager, config)
        self.threads = config.get('threads', 1)
        self.result = CrackingResult(success=False, attempts=0)
        self.result_lock = threading.Lock()
        self.stop_event = threading.Event()
        
        # BFS configuration
        self.min_length = config.get('min_length', 1)
        self.max_length = config.get('max_length', 5)
        self.charset = self._get_charset(config)
        
        # Demo-specific configurations
        self.show_progress = config.get('show_progress', True)
        self.max_attempts = config.get('max_attempts', 500000)
        self.demo_mode = config.get('demo_mode', False)
        
        # For demonstration visualization
        self.current_length = self.min_length
        self.current_prefix = ""
        
        # Performance tracking
        self.attempts = 0
        self.start_time = 0
    
    def _get_charset(self, config: Dict[str, Any]) -> str:
        """
        Get the character set to use based on configuration.
        
        Args:
            config: Configuration dict
            
        Returns:
            String containing all characters to use
        """
        charset_config = config.get('charset', 'lower+digits')
        charset = ""
        
        if 'lower' in charset_config:
            charset += string.ascii_lowercase
        if 'upper' in charset_config:
            charset += string.ascii_uppercase
        if 'digits' in charset_config:
            charset += string.digits
        if 'special' in charset_config:
            charset += string.punctuation
        if 'space' in charset_config:
            charset += ' '
        if charset_config == 'all':
            charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        
        # Custom charset overrides predefined options
        custom_charset = config.get('custom_charset')
        if custom_charset:
            charset = custom_charset
        
        # Ensure we have at least some characters
        if not charset:
            charset = string.ascii_lowercase + string.digits
        
        # Optimize by prioritizing most common characters first
        return self._optimize_charset(charset)
    
    def _optimize_charset(self, charset: str) -> str:
        """
        Optimize character set by prioritizing most common characters.
        
        Args:
            charset: Original character set
            
        Returns:
            Optimized character set
        """
        # Most common characters in passwords by frequency
        common_chars = 'etaoinshrdlucmfwypvbgkjqxz1234567890'
        
        # Extract characters that exist in both sets, maintaining common order
        optimized = ''.join(c for c in common_chars if c in charset)
        
        # Add remaining characters that weren't in common list
        remaining = ''.join(c for c in charset if c not in optimized)
        
        return optimized + remaining
    
    def execute(self) -> CrackingResult:
        """
        Execute the brute force attack using BFS.
        
        Returns:
            CrackingResult containing the outcome
        """
        print(f"[+] Starting targeted brute force attack using BFS")
        print(f"[*] Using {self.threads} thread(s) for cracking")
        print(f"[*] Character set: '{self.charset}'")
        print(f"[*] Password length range: {self.min_length} to {self.max_length}")
        print(f"[*] Target hash: {self.hash_manager.target_hash}")
        
        # Initialize the result
        self.result = CrackingResult(success=False, attempts=0)
        self.start_time = time.time()
        
        # Use BFS to search password space
        success = self._bfs_search()
        
        # Finalize result
        self.result.attempts = self.attempts
        
        # Add details to result
        self.result.details = {
            'elapsed_time': time.time() - self.start_time,
            'charset': self.charset,
            'min_length': self.min_length,
            'max_length': self.max_length,
            'charset_size': len(self.charset),
            'theoretical_space': sum(len(self.charset) ** i for i in range(self.min_length, self.max_length + 1))
        }
        
        return self.result
    
    def _bfs_search(self) -> bool:
        """
        Perform a breadth-first search of the password space.
        
        Returns:
            True if password found, False otherwise
        """
        # Create work queue for BFS
        # We use a deque for efficiency, but conceptually this is a queue
        work_queue = deque([''])  # Start with empty string
        
        # Display progress bar
        theoretical_max = min(
            self.max_attempts,
            sum(len(self.charset) ** i for i in range(self.min_length, self.max_length + 1))
        )
        
        with tqdm(total=theoretical_max, disable=not self.show_progress,
                  desc="Brute force BFS", unit="pwd") as pbar:
            
            # BFS loop
            while work_queue and not self.result.success:
                # Get next candidate prefix
                current = work_queue.popleft()
                
                # For visualization in demo mode
                if self.demo_mode and len(current) > 0:
                    self.current_length = len(current)
                    self.current_prefix = current
                
                # If we're within the valid length range, check this password
                if self.min_length <= len(current) <= self.max_length:
                    with self.result_lock:
                        self.attempts += 1
                        
                        if self.hash_manager.verify(current):
                            self.result.success = True
                            self.result.password = current
                            return True
                    
                    # Update progress
                    pbar.update(1)
                
                # If we haven't reached max length, expand to next level
                if len(current) < self.max_length:
                    for char in self.charset:
                        next_candidate = current + char
                        work_queue.append(next_candidate)
                
                # Check if we've reached max attempts
                if self.attempts >= self.max_attempts:
                    print(f"[!] Reached maximum attempts ({self.max_attempts})")
                    break
                
                # Demo mode: add small delay for visualization
                if self.demo_mode and len(current) > 0:
                    time.sleep(0.00005)  # Very slight delay for visual effect
        
        return self.result.success
    
    def get_visualization_state(self) -> Dict[str, Any]:
        """
        Get the current state for visualization in demo mode.
        
        Returns:
            Dictionary with current BFS state
        """
        return {
            'current_length': self.current_length,
            'current_prefix': self.current_prefix,
            'attempts': self.attempts,
            'charset': self.charset
        }