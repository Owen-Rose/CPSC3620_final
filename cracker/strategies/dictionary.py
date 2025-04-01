"""
Advanced Dictionary Attack Strategy Module

This module implements a highly optimized dictionary-based password cracking strategy
with sophisticated pattern recognition and transformation capabilities.
"""

import os
import time
import threading
import mmap
import queue
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Set, Optional, Tuple, Iterator, Deque
from collections import deque
import io
from dataclasses import dataclass, field
import itertools

from tqdm import tqdm

from cracker.strategies.base import BaseStrategy, CrackingResult
from cracker.hash_manager import HashManager
from cracker.utilities.transform import PasswordTransformer
from cracker.utilities.rule_engine import (
    RuleEngine, 
    KeyboardPatternGenerator, 
    MultiWordGenerator
)


class StageTracker:
    """
    Tracks progression through multiple attack stages.
    """
    def __init__(self):
        self.stages = []
        self.current_stage = 0
        self.start_time = 0
        
    def add_stage(self, name: str, description: str):
        """Add a stage to track."""
        self.stages.append({
            'name': name,
            'description': description,
            'completed': False,
            'start_time': 0,
            'end_time': 0,
            'attempts': 0
        })
        
    def start_stage(self, index: int):
        """Start tracking a specific stage."""
        if 0 <= index < len(self.stages):
            self.current_stage = index
            self.stages[index]['start_time'] = time.time()
            print(f"[*] Stage {index+1}: {self.stages[index]['description']}")
            
    def complete_stage(self, attempts: int):
        """Mark the current stage as complete."""
        if 0 <= self.current_stage < len(self.stages):
            stage = self.stages[self.current_stage]
            stage['completed'] = True
            stage['end_time'] = time.time()
            stage['attempts'] = attempts
            
            duration = stage['end_time'] - stage['start_time']
            print(f"[*] Completed stage {self.current_stage+1} in {duration:.2f}s ({attempts:,} attempts)")
            
    def get_summary(self) -> Dict:
        """Get a summary of all stages."""
        return {
            'stages': self.stages,
            'completed_stages': sum(1 for s in self.stages if s['completed']),
            'total_stages': len(self.stages),
            'total_attempts': sum(s['attempts'] for s in self.stages if s['completed']),
            'total_time': sum(s['end_time'] - s['start_time'] for s in self.stages if s['completed'])
        }


class DictionaryAttack(BaseStrategy):
    """
    Advanced dictionary-based password cracking strategy with intelligent
    prioritization and sophisticated transformation capabilities.
    """
    
    def __init__(self, hash_manager: HashManager, config: Dict[str, Any]):
        """
        Initialize the dictionary attack strategy.
        
        Args:
            hash_manager: The hash manager for verification
            config: Configuration parameters
        """
        super().__init__(hash_manager, config)
        self.dictionary_path = config['dictionary_path']
        self.threads = config.get('threads', 1)
        self.result = CrackingResult(success=False, attempts=0)
        self.result_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.apply_transformations = config.get('transformations', True)
        self.chunk_size = config.get('chunk_size', 50000)
        self.checkpoint_file = config.get('checkpoint_file', None)
        self.max_transformations = config.get('max_transformations', 15)
        self.quick_mode = config.get('quick_mode', True)
        self.advanced_mode = config.get('advanced_mode', True)
        
        # New: Priority optimization settings
        self.prioritize_common = config.get('prioritize_common', True)
        self.prioritize_length = config.get('prioritize_length', True)
        self.target_pattern = config.get('target_pattern', None)
        
        # File information
        self.file_size = os.path.getsize(self.dictionary_path)
        self.word_count = self._estimate_word_count()
        
        # Performance tracking
        self.passwords_checked = 0
        self.batches_processed = 0
        self.start_time = 0
        
        # Work queues and coordination
        self.result_queue = queue.Queue()
        self.work_queues = [queue.Queue() for _ in range(self.threads)]
        self.work_distribution = [0] * self.threads  # Track work distribution for load balancing
        
        # Instantiate rule engine
        self.rule_engine = RuleEngine()
        
        # Stage tracker for multi-stage attack
        self.stage_tracker = StageTracker()
        self._setup_stages()
    
    def _setup_stages(self):
        """Set up the stages for the multi-stage attack strategy."""
        self.stage_tracker.add_stage(
            "common_passwords", "Trying common passwords and variations"
        )
        self.stage_tracker.add_stage(
            "dictionary_no_transform", "Testing dictionary words without transformations"
        )
        self.stage_tracker.add_stage(
            "basic_transformations", "Applying basic transformations to promising words"
        )
        self.stage_tracker.add_stage(
            "advanced_transformations", "Applying advanced pattern-based transformations"
        )
        self.stage_tracker.add_stage(
            "keyboard_patterns", "Testing keyboard pattern variants"
        )
        self.stage_tracker.add_stage(
            "combined_words", "Trying multi-word combinations"
        )
    
    def _estimate_word_count(self) -> int:
        """
        Estimate the number of words in the dictionary based on file size and sampling.
        
        Returns:
            Estimated number of words
        """
        try:
            # For very large files, use sampling
            if self.file_size > 10 * 1024 * 1024:  # 10 MB
                # Sample different parts of the file
                samples = []
                with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                    # Sample beginning
                    f.seek(0)
                    beginning = [next(f) for _ in range(1000) if f]
                    
                    # Sample middle
                    f.seek(max(0, self.file_size // 2 - 5000))
                    # Skip to next complete line
                    f.readline()
                    middle = [next(f) for _ in range(1000) if f]
                    
                    # Sample end
                    f.seek(max(0, self.file_size - 10000))
                    f.readline()  # Skip to next complete line
                    end = [next(f) for _ in range(1000) if f]
                
                all_samples = beginning + middle + end
                
                if not all_samples:
                    return max(1, self.file_size // 10)
                
                # Calculate average bytes per line across all samples
                avg_bytes_per_line = sum(len(line.encode('utf-8')) for line in all_samples) / len(all_samples)
                
                # Estimate total lines
                estimated_lines = int(self.file_size / avg_bytes_per_line)
                
                return max(1, estimated_lines)
            else:
                # For smaller files, count exact lines
                with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                    return sum(1 for line in f if line.strip())
                
        except Exception as e:
            print(f"[!] Error estimating word count: {e}")
            # Fallback to a rough estimate
            return max(1, self.file_size // 10)
    
    def execute(self) -> CrackingResult:
        """
        Execute the multi-stage dictionary attack strategy.
        
        Returns:
            CrackingResult containing the outcome of the cracking attempt
        """
        print(f"[+] Starting advanced dictionary attack using {self.dictionary_path}")
        print(f"[*] Estimated dictionary size: ~{self.word_count:,} words")
        print(f"[*] Using {self.threads} thread(s) for cracking")
        print(f"[*] Target hash: {self.hash_manager.target_hash}")
        
        if self.apply_transformations:
            print(f"[*] Password transformations: Enabled (max {self.max_transformations} per word)")
        else:
            print(f"[*] Password transformations: Disabled")
            
        # Initialize the result
        self.result = CrackingResult(success=False, attempts=0)
        self.start_time = time.time()
        
        # Execute multi-stage attack strategy
        
        # Stage 1: Try common passwords
        if self.prioritize_common:
            self.stage_tracker.start_stage(0)
            if self._try_common_passwords_stage():
                return self._finalize_result()
            self.stage_tracker.complete_stage(self.result.attempts)
        
        # Stage 2: Test dictionary words without transformations
        if self.quick_mode:
            self.stage_tracker.start_stage(1)
            if self._dictionary_no_transform_stage():
                return self._finalize_result()
            self.stage_tracker.complete_stage(self.result.attempts)
        
        # If transformations are enabled, proceed to transformation stages
        if self.apply_transformations:
            # Stage 3: Apply basic transformations to promising words
            self.stage_tracker.start_stage(2)
            if self._basic_transformations_stage():
                return self._finalize_result()
            self.stage_tracker.complete_stage(self.result.attempts)
            
            # Stage 4: Apply advanced transformations
            if self.advanced_mode:
                self.stage_tracker.start_stage(3)
                if self._advanced_transformations_stage():
                    return self._finalize_result()
                self.stage_tracker.complete_stage(self.result.attempts)
                
                # Stage 5: Test keyboard patterns
                self.stage_tracker.start_stage(4)
                if self._keyboard_patterns_stage():
                    return self._finalize_result()
                self.stage_tracker.complete_stage(self.result.attempts)
                
                # Stage 6: Try multi-word combinations
                self.stage_tracker.start_stage(5)
                if self._combined_words_stage():
                    return self._finalize_result()
                self.stage_tracker.complete_stage(self.result.attempts)
        
        # Password not found after all stages
        return self._finalize_result()
    
    def _finalize_result(self) -> CrackingResult:
        """
        Finalize the result with timing and statistics.
        
        Returns:
            Completed CrackingResult
        """
        # Calculate elapsed time
        elapsed = time.time() - self.start_time
        
        # Get stage summary
        stage_summary = self.stage_tracker.get_summary()
        
        # Add details to result
        self.result.details = {
            'dictionary_path': self.dictionary_path,
            'thread_count': self.threads,
            'elapsed_time': elapsed,
            'words_processed': self.passwords_checked,
            'stages': stage_summary,
            'transformations_enabled': self.apply_transformations,
            'advanced_mode': self.advanced_mode
        }
        
        return self.result
    
    def _try_common_passwords_stage(self) -> bool:
        """
        Stage 1: Try common passwords and variations.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Trying common passwords and variations...")
        
        # Get enhanced list of common passwords
        common_passwords = PasswordTransformer.get_common_passwords(300)
        
        # Add targeted variants
        common_variants = PasswordTransformer.generate_variants_for_common_words(
            common_passwords, max_per_word=8
        )
        
        # Add some special interest passwords that might be relevant for students
        special_passwords = [
            "password", "password123", "123456", "qwerty", "letmein", "admin", 
            "welcome", "p@ssw0rd", "student", "test123", "hello123", "12345678", 
            "iloveyou", "sunshine", "princess", "dragon", "football", "baseball", 
            "superman", "batman", "trustno1", "whatever", "welcome1", "monkey",
            # Academic-related
            "student", "teacher", "school", "college", "university", "campus",
            "class", "semester", "study", "graduate", "education", "homework",
            # Years
            "2023", "2024", "2022", "2021"
        ]
        
        for pwd in special_passwords:
            if pwd not in common_variants:
                common_variants.append(pwd)
        
        # Additional educational domain variations
        edu_variations = []
        for base in ["student", "admin", "password", "welcome", "school"]:
            edu_variations.extend([
                f"{base}123", f"{base}2023", f"{base}2024", f"{base}!",
                f"{base}#", base.capitalize(), base.upper(),
                f"{base}123!", f"{base}2023!", 
            ])
        
        # Add these variations
        for var in edu_variations:
            if var not in common_variants:
                common_variants.append(var)
        
        # Show progress
        with tqdm(total=len(common_variants), desc="Common passwords", unit="pwd") as pbar:
            # Process in batches for efficiency
            batch_size = 100
            for i in range(0, len(common_variants), batch_size):
                batch = common_variants[i:i+batch_size]
                
                # Try each password in the batch
                for password in batch:
                    with self.result_lock:
                        self.result.attempts += 1
                        self.passwords_checked += 1
                    
                    if self.hash_manager.verify(password):
                        with self.result_lock:
                            self.result.success = True
                            self.result.password = password
                        return True
                
                # Update progress
                pbar.update(len(batch))
        
        return False
    
    def _dictionary_no_transform_stage(self) -> bool:
        """
        Stage 2: Process dictionary words without transformations.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Processing dictionary words (no transformations)...")
        
        # Process the dictionary using appropriate method based on size
        if self.file_size > 100 * 1024 * 1024:  # 100 MB
            print("[*] Using memory mapping for efficient file access")
            chunks_generator = self._memory_map_dictionary()
        else:
            chunks_generator = self._read_dictionary_in_chunks()
        
        # Create progress bar
        with tqdm(total=self.word_count, desc="Dictionary scan", unit="word") as pbar:
            # Process each chunk
            for chunk in chunks_generator:
                # Check if password found
                if self.result.success:
                    break
                    
                # Process the chunk
                if self._check_words_batch(chunk):
                    return True
                
                # Update progress
                pbar.update(len(chunk))
                
                # Check if we should stop
                if self.stop_event.is_set():
                    break
        
        return False
    
    def _basic_transformations_stage(self) -> bool:
        """
        Stage 3: Apply basic transformations to promising words.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Applying basic transformations to promising words...")
        
        # Get a reasonable subset of words to transform
        promising_words = self._get_promising_words(limit=5000)
        
        # Create progress bar
        with tqdm(total=len(promising_words), desc="Basic transforms", unit="word") as pbar:
            # Process in batches
            batch_size = 100
            for i in range(0, len(promising_words), batch_size):
                batch = promising_words[i:i+batch_size]
                
                # Apply basic transformations to each word
                for word in batch:
                    # Generate transformations
                    transforms = PasswordTransformer.smart_transform(
                        word, max_variants=10
                    )
                    
                    # Check the transformations
                    if self._check_words_batch(transforms):
                        return True
                
                # Update progress
                pbar.update(len(batch))
                
                # Check if we should stop
                if self.result.success or self.stop_event.is_set():
                    break
        
        return False
    
    def _advanced_transformations_stage(self) -> bool:
        """
        Stage 4: Apply advanced transformations to high-value words.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Applying advanced pattern-based transformations...")
        
        # Get a smaller set of high-value words
        high_value_words = self._get_promising_words(limit=1000)
        
        # Create progress bar
        with tqdm(total=len(high_value_words), desc="Advanced transforms", unit="word") as pbar:
            # Process in smaller batches
            batch_size = 50
            for i in range(0, len(high_value_words), batch_size):
                batch = high_value_words[i:i+batch_size]
                
                # Apply advanced transformations to each word
                for word in batch:
                    # Generate advanced transformations
                    transforms = PasswordTransformer.advanced_transform(
                        word, max_variants=self.max_transformations
                    )
                    
                    # Check the transformations
                    if self._check_words_batch(transforms):
                        return True
                
                # Update progress
                pbar.update(len(batch))
                
                # Check if we should stop
                if self.result.success or self.stop_event.is_set():
                    break
        
        return False
    
    def _keyboard_patterns_stage(self) -> bool:
        """
        Stage 5: Try keyboard pattern variations.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Testing keyboard pattern variations...")
        
        # Define common keyboard patterns to check
        patterns = [
            "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx",
            "qwertyuiop", "asdfghjkl", "zxcvbnm", "1q2w3e", "1q2w3e4r",
            "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm", 
            "12345", "123456", "1234567", "12345678", "123456789",
            "987654321", "87654321", "7654321", "654321", "54321",
            "admin", "password", "login", "user"
        ]
        
        # Process patterns
        with tqdm(total=len(patterns), desc="Keyboard patterns", unit="pattern") as pbar:
            for pattern in patterns:
                # Generate keyboard pattern variations
                variants = KeyboardPatternGenerator.generate_variants(pattern, max_variants=15)
                
                # Always include the original pattern
                if pattern not in variants:
                    variants.append(pattern)
                
                # Check the variants
                if self._check_words_batch(variants):
                    return True
                
                # Update progress
                pbar.update(1)
                
                # Check if we should stop
                if self.result.success or self.stop_event.is_set():
                    break
        
        return False
    
    def _combined_words_stage(self) -> bool:
        """
        Stage 6: Try multi-word combinations.
        
        Returns:
            True if password found, False otherwise
        """
        print("[*] Trying multi-word combinations...")
        
        # Get common base words
        common_words = PasswordTransformer.COMMON_WORDS[:50]
        
        # Add special interest words
        special_words = ["welcome", "hello", "student", "admin", "test", "user", 
                       "login", "pass", "school", "college", "letme", "please"]
        
        for word in special_words:
            if word not in common_words:
                common_words.append(word)
        
        # Define connectors
        connectors = ["", "123", "2023", "2024", "!", "#", "_", "."]
        
        # Generate combinations
        combinations = []
        
        # Limit to control explosion
        max_combinations = 2000
        
        # Create word + connector + word combinations
        with tqdm(total=len(common_words), desc="Word combinations", unit="base") as pbar:
            for word1 in common_words:
                # Use a subset of second words to avoid explosion
                for word2 in common_words[:20]:
                    for connector in connectors[:4]:  # Limit connectors too
                        combo = word1 + connector + word2
                        combinations.append(combo)
                        
                        # Also try with capitalization if using empty connector
                        if connector == "":
                            combinations.append(word1 + word2.capitalize())
                        
                        # Check if we've reached our limit
                        if len(combinations) >= max_combinations:
                            break
                    
                    if len(combinations) >= max_combinations:
                        break
                
                # Update progress
                pbar.update(1)
                
                # Process batch to avoid memory issues
                if len(combinations) >= 200 or len(combinations) >= max_combinations:
                    if self._check_words_batch(combinations):
                        return True
                    combinations = []
                
                # Check if we should stop
                if self.result.success or self.stop_event.is_set():
                    break
        
        # Check any remaining combinations
        if combinations and not self.result.success and not self.stop_event.is_set():
            if self._check_words_batch(combinations):
                return True
        
        return False
    
    def _read_dictionary_in_chunks(self) -> Iterator[List[str]]:
        """
        Memory-efficient generator that yields chunks of the dictionary file.
        
        Yields:
            Chunks of words from the dictionary
        """
        words_chunk = []
        
        try:
            with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        words_chunk.append(word)
                        
                        if len(words_chunk) >= self.chunk_size:
                            yield words_chunk
                            words_chunk = []
            
            # Yield any remaining words
            if words_chunk:
                yield words_chunk
                
        except Exception as e:
            print(f"[!] Error reading dictionary: {e}")
            if words_chunk:
                yield words_chunk
    
    def _memory_map_dictionary(self) -> Iterator[List[str]]:
        """
        Use memory mapping for efficient access to very large files.
        
        Yields:
            Chunks of words from the dictionary
        """
        try:
            with open(self.dictionary_path, 'r+b') as f:
                # Memory map the file
                mm = mmap.mmap(f.fileno(), 0)
                
                # Read lines in chunks
                current_chunk = []
                current_pos = 0
                
                while current_pos < mm.size():
                    # Find next line
                    line_end = mm.find(b'\n', current_pos)
                    if line_end == -1:
                        # Last line
                        line = mm[current_pos:].decode('utf-8', errors='ignore').strip()
                        if line:
                            current_chunk.append(line)
                        break
                    
                    # Extract the line
                    line = mm[current_pos:line_end].decode('utf-8', errors='ignore').strip()
                    current_pos = line_end + 1
                    
                    if line:
                        current_chunk.append(line)
                        
                        if len(current_chunk) >= self.chunk_size:
                            yield current_chunk
                            current_chunk = []
                
                # Yield any remaining words
                if current_chunk:
                    yield current_chunk
                    
                # Close the memory map
                mm.close()
                
        except Exception as e:
            print(f"[!] Error using memory mapping: {e}")
            # Fall back to regular chunk reading
            yield from self._read_dictionary_in_chunks()
    
    def _check_words_batch(self, words: List[str]) -> bool:
        """
        Check a batch of words against the target hash.
        
        Args:
            words: List of words to check
            
        Returns:
            True if password found, False otherwise
        """
        # Skip if already found or should stop
        if self.result.success or self.stop_event.is_set():
            return False
        
        # Use multi-threading for larger batches
        if len(words) > 1000 and self.threads > 1:
            return self._check_words_threaded(words)
        
        # Process sequentially for smaller batches
        for word in words:
            with self.result_lock:
                self.result.attempts += 1
                self.passwords_checked += 1
            
            if self.hash_manager.verify(word):
                with self.result_lock:
                    self.result.success = True
                    self.result.password = word
                return True
            
            # Check if we should stop
            if self.stop_event.is_set():
                return False
        
        return False
    
    def _check_words_threaded(self, words: List[str]) -> bool:
        """
        Check words using multiple threads for better performance.
        
        Args:
            words: List of words to check
            
        Returns:
            True if password found, False otherwise
        """
        # Split the workload
        chunks = self._split_list(words, self.threads)
        
        # Use ThreadPoolExecutor to process chunks
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit tasks
            futures = [executor.submit(self._check_word_chunk, chunk) for chunk in chunks]
            
            # Wait for tasks to complete
            for future in futures:
                if future.result():
                    # Password found
                    return True
                
                # Check if we should stop
                if self.result.success or self.stop_event.is_set():
                    return self.result.success
        
        return False
    
    def _check_word_chunk(self, words: List[str]) -> bool:
        """
        Check a chunk of words in a worker thread.
        
        Args:
            words: Chunk of words to check
            
        Returns:
            True if password found, False otherwise
        """
        for word in words:
            # Check if we should stop
            if self.result.success or self.stop_event.is_set():
                return False
            
            # Track attempts
            with self.result_lock:
                self.result.attempts += 1
                self.passwords_checked += 1
            
            # Check the word
            if self.hash_manager.verify(word):
                with self.result_lock:
                    self.result.success = True
                    self.result.password = word
                # Signal other threads to stop
                self.stop_event.set()
                return True
        
        return False
    
    def _get_promising_words(self, limit: int = 5000) -> List[str]:
        """
        Get a list of promising words from the dictionary that are worth transforming.
        
        Args:
            limit: Maximum number of words to return
            
        Returns:
            List of promising words
        """
        promising = []
        seen = set()
        
        # Always include common words
        common_words = PasswordTransformer.COMMON_WORDS[:100]
        for word in common_words:
            promising.append(word)
            seen.add(word)
        
        # Read from dictionary
        try:
            with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if not word or word in seen:
                        continue
                    
                    # Filter based on length if prioritizing by length
                    if self.prioritize_length:
                        # Favor words between 4-10 characters
                        if 4 <= len(word) <= 10:
                            promising.append(word)
                            seen.add(word)
                    else:
                        # Just add all words
                        promising.append(word)
                        seen.add(word)
                    
                    # Check if we have enough words
                    if len(promising) >= limit:
                        break
                        
        except Exception as e:
            print(f"[!] Error reading dictionary for promising words: {e}")
        
        return promising
    
    def _split_list(self, lst: List[Any], num_parts: int) -> List[List[Any]]:
        """
        Split a list into approximately equal parts.
        
        Args:
            lst: The list to split
            num_parts: Number of parts to create
            
        Returns:
            List of list parts
        """
        # Handle edge case
        if len(lst) <= num_parts:
            return [lst[i:i+1] for i in range(len(lst))]
        
        # Calculate part size
        part_size = len(lst) // num_parts
        remainder = len(lst) % num_parts
        
        # Create parts
        parts = []
        start = 0
        
        for i in range(num_parts):
            # Add one extra element to first 'remainder' parts
            end = start + part_size + (1 if i < remainder else 0)
            parts.append(lst[start:end])
            start = end
        
        return parts