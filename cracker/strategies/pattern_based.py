"""
Pattern-Based Attack Strategy Module

This module implements a pattern-based password cracking strategy that applies
transformation rules based on common password patterns and heuristics.
"""

import time
import queue
import threading
from typing import Dict, Any, List, Set, Optional
from collections import deque

from tqdm import tqdm

from cracker.strategies.base import BaseStrategy, CrackingResult
from cracker.hash_manager import HashManager
from cracker.utilities.rule_engine import RuleEngine
from cracker.utilities.transform import PasswordTransformer


class PatternBasedAttack(BaseStrategy):
    """
    Strategy that applies pattern-based transformations to crack passwords.
    Uses rule-based approach with prioritization by probability.
    """
    
    def __init__(self, hash_manager: HashManager, config: Dict[str, Any]):
        """
        Initialize the pattern-based attack strategy.
        
        Args:
            hash_manager: The hash manager for verification
            config: Configuration parameters
        """
        super().__init__(hash_manager, config)
        self.threads = config.get('threads', 1)
        self.result = CrackingResult(success=False, attempts=0)
        self.result_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.max_transformations = config.get('max_transformations', 15)
        self.verbose = config.get('verbose', False)
        
        # Demo-specific configurations
        self.show_progress = config.get('show_progress', True)
        self.max_attempts = config.get('max_attempts', 10000)
        self.target_pattern = config.get('target_pattern', None)
        self.demo_mode = config.get('demo_mode', False)
        
        # Rule engine for transformations
        self.rule_engine = RuleEngine()
        
        # Pattern categories with sample base words
        self.pattern_categories = {
            'leet': ['password', 'hacker', 'elite', 'master', 'secret', 'secure', 
                    'access', 'admin', 'login', 'letmein', 'private', 'system'],
            'keyboard': ['qwerty', 'asdfgh', 'zxcvbn', '1234', 'qazwsx', '12345'],
            'common_words': PasswordTransformer.COMMON_WORDS[:50],
            'year_patterns': ['password', 'access', 'admin', 'login', 'user', 'system'],
            'special_char': ['password', 'secure', 'protected', 'private', 'login', 'admin']
        }
        
        # Performance tracking
        self.attempts = 0
        self.start_time = 0
    
    def execute(self) -> CrackingResult:
        """
        Execute the pattern-based attack strategy.
        
        Returns:
            CrackingResult containing the outcome of the cracking attempt
        """
        print(f"[+] Starting pattern-based attack")
        print(f"[*] Using {self.threads} thread(s) for cracking")
        print(f"[*] Target hash: {self.hash_manager.target_hash}")
        
        # Initialize the result
        self.result = CrackingResult(success=False, attempts=0)
        self.start_time = time.time()
        
        # Select attack approach based on target pattern or use prioritized method
        if self.target_pattern and self.target_pattern in self.pattern_categories:
            return self._attack_specific_pattern(self.target_pattern)
        else:
            return self._prioritized_pattern_attack()
    
    def _prioritized_pattern_attack(self) -> CrackingResult:
        """
        Run a prioritized attack trying multiple pattern categories in order of likelihood.
        
        Returns:
            CrackingResult containing the outcome
        """
        # Define pattern categories in order of priority
        pattern_priority = [
            ('leet', 'Applying leet speak transformations'),
            ('keyboard', 'Testing keyboard pattern variants'),
            ('common_words', 'Trying common word transformations'),
            ('year_patterns', 'Applying year/date patterns'),
            ('special_char', 'Testing special character variations')
        ]
        
        # Create a work queue for patterns
        work_queue = queue.Queue()
        
        # Add patterns to queue in priority order
        for pattern_key, description in pattern_priority:
            if pattern_key in self.pattern_categories:
                work_queue.put((pattern_key, self.pattern_categories[pattern_key], description))
        
        with tqdm(total=self.max_attempts, disable=not self.show_progress, 
                  desc="Pattern attack", unit="pwd") as pbar:
            
            # Process patterns until success or queue is empty
            while not work_queue.empty() and not self.result.success:
                # Get next pattern category
                pattern_key, base_words, description = work_queue.get()
                
                print(f"[*] {description}")
                
                # Adjust word set size based on pattern complexity
                word_limit = min(len(base_words), 20 if pattern_key == 'common_words' else 10)
                
                # Process the pattern with the base words
                success = self._process_pattern(pattern_key, base_words[:word_limit], pbar)
                
                # If successful, break
                if success:
                    break
                
                # Update progress bar
                pbar.update(min(1000, self.max_attempts - self.attempts))
            
        # Finalize result
        self.result.attempts = self.attempts
        
        # Calculate elapsed time
        elapsed = time.time() - self.start_time
        
        # Add details to result
        pattern_info = {pattern: len(words) for pattern, words in self.pattern_categories.items()}
        
        self.result.details = {
            'elapsed_time': elapsed,
            'pattern_categories': pattern_info,
            'transformations_applied': self.attempts
        }
        
        return self.result
    
    def _attack_specific_pattern(self, pattern_key: str) -> CrackingResult:
        """
        Run an attack focused on a specific pattern category.
        
        Args:
            pattern_key: Key of the pattern category to use
            
        Returns:
            CrackingResult containing the outcome
        """
        if pattern_key not in self.pattern_categories:
            print(f"[!] Unknown pattern category: {pattern_key}")
            return CrackingResult(success=False, attempts=0)
        
        base_words = self.pattern_categories[pattern_key]
        
        with tqdm(total=self.max_attempts, disable=not self.show_progress,
                  desc=f"{pattern_key} attack", unit="pwd") as pbar:
            
            # Process the pattern with all base words
            self._process_pattern(pattern_key, base_words, pbar)
        
        # Finalize result
        self.result.attempts = self.attempts
        
        # Add details to result
        self.result.details = {
            'elapsed_time': time.time() - self.start_time,
            'pattern_category': pattern_key,
            'base_words_count': len(base_words),
            'transformations_applied': self.attempts
        }
        
        return self.result
    
    def _process_pattern(self, pattern_key: str, base_words: List[str], 
                        progress_bar: Optional[tqdm] = None) -> bool:
        """
        Process a specific pattern category with the given base words.
        
        Args:
            pattern_key: Key of the pattern category
            base_words: List of words to transform
            progress_bar: Optional tqdm progress bar
            
        Returns:
            True if password found, False otherwise
        """
        # Define specific rules for each pattern category
        pattern_rules = {
            'leet': ["leet_basic", "leet_advanced", "capital_leet"],
            'keyboard': [],  # Special handling below
            'common_words': ["lowercase", "capitalize", "uppercase", 
                            "common_numbers", "common_years", "pattern_123"],
            'year_patterns': ["common_years", "capital_year"],
            'special_char': ["common_special", "common_patterns"]
        }
        
        # Define transformations based on pattern type
        for word in base_words:
            # Skip if we've reached max attempts or found the password
            if self.attempts >= self.max_attempts or self.result.success:
                return self.result.success
            
            # Generate transformations based on pattern type
            transformations = []
            
            if pattern_key == 'keyboard':
                # For keyboard patterns, generate variations
                # Since KeyboardPatternGenerator might not be accessible, we'll implement inline
                if word in ['qwerty', 'asdfgh', 'zxcvbn']:
                    # For demonstration, generate some basic keyboard pattern variants
                    transformations = [
                        word, word + '123', word + '123!', word + '!', 
                        word.capitalize(), word.upper(), 
                        ''.join(word[i].upper() if i % 2 == 0 else word[i] for i in range(len(word)))
                    ]
                else:
                    # For non-standard keyboard patterns
                    transformations = [
                        word, word + '123', word + '!', word.capitalize(), word.upper()
                    ]
            else:
                # Use rule engine with pattern-specific rules
                rules = pattern_rules.get(pattern_key, [])
                if rules:
                    # Apply each rule and collect transformations
                    transformations = [word]  # Start with original word
                    for rule in rules:
                        try:
                            result = self.rule_engine.apply_rule(word, rule)
                            if isinstance(result, str):
                                transformations.append(result)
                            elif isinstance(result, list):
                                transformations.extend(result)
                        except Exception as e:
                            if self.verbose:
                                print(f"[!] Error applying rule {rule}: {e}")
                else:
                    # Fallback to basic transformations
                    transformations = [
                        word, word.capitalize(), word.upper(), 
                        word + '123', word + '!', word + '2023',
                        word.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
                    ]
            
            # Check the transformations
            if self._check_passwords(transformations, progress_bar):
                return True
            
            # Demo pause: makes the display more visual for educational purposes
            if self.demo_mode and pattern_key in ['leet', 'keyboard']:
                time.sleep(0.05)  # Brief pause for visual effect
        
        return False
    
    def _check_passwords(self, passwords: List[str], 
                        progress_bar: Optional[tqdm] = None) -> bool:
        """
        Check a list of passwords against the target hash.
        
        Args:
            passwords: List of passwords to check
            progress_bar: Optional tqdm progress bar
            
        Returns:
            True if password found, False otherwise
        """
        for password in passwords:
            # Skip if already found
            if self.result.success:
                return True
            
            # Track attempts
            with self.result_lock:
                self.attempts += 1
                
                # Check the password
                if self.hash_manager.verify(password):
                    self.result.success = True
                    self.result.password = password
                    return True
            
            # Update progress bar
            if progress_bar is not None:
                progress_bar.update(1)
            
            # Check if we've reached max attempts
            if self.attempts >= self.max_attempts:
                return False
        
        return False