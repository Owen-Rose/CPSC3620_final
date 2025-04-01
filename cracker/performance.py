"""
Performance Monitor Module

This module provides functionality for tracking and reporting performance
metrics during password cracking operations.
"""

import time
from typing import Dict, Any, Optional


class PerformanceTracker:
    """
    Tracks performance metrics for password cracking operations.
    """
    
    def __init__(self):
        """
        Initialize a new performance tracker.
        """
        self.start_time = None
        self.end_time = None
        self.checkpoints = {}
    
    def start(self) -> None:
        """
        Start the performance timer.
        """
        self.start_time = time.time()
    
    def stop(self) -> None:
        """
        Stop the performance timer.
        """
        self.end_time = time.time()
    
    def checkpoint(self, name: str) -> None:
        """
        Record a checkpoint with the current time.
        
        Args:
            name: Name of the checkpoint
        """
        self.checkpoints[name] = time.time()
    
    def elapsed_seconds(self) -> float:
        """
        Calculate the elapsed time in seconds.
        
        Returns:
            Elapsed time in seconds, or time since start if not stopped
        """
        end = self.end_time if self.end_time is not None else time.time()
        return end - self.start_time if self.start_time is not None else 0
    
    def checkpoint_elapsed(self, name: str) -> Optional[float]:
        """
        Calculate the elapsed time since a specific checkpoint.
        
        Args:
            name: Name of the checkpoint
            
        Returns:
            Elapsed time in seconds since the checkpoint, or None if checkpoint not found
        """
        if name not in self.checkpoints:
            return None
        
        end = self.end_time if self.end_time is not None else time.time()
        return end - self.checkpoints[name]
    
    def calculate_rate(self, attempts: int) -> float:
        """
        Calculate the rate of attempts per second.
        
        Args:
            attempts: Number of attempts made
            
        Returns:
            Rate of attempts per second
        """
        elapsed = self.elapsed_seconds()
        return attempts / elapsed if elapsed > 0 else 0
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of performance metrics.
        
        Returns:
            Dictionary containing performance metrics
        """
        return {
            'elapsed_seconds': self.elapsed_seconds(),
            'checkpoints': {
                name: self.checkpoint_elapsed(name)
                for name in self.checkpoints
            }
        }