#!/usr/bin/env python3
"""
Advanced Password Cracker Tool - Main Entry Point

This script serves as the entry point for the enhanced password cracking tool,
optimized for tackling complex passwords with sophisticated pattern recognition.
"""

import sys
import time
import os
from cracker.cli import parse_arguments, print_banner, print_summary, get_dictionary_info
from cracker.strategies import get_strategy
from cracker.performance import PerformanceTracker
from cracker.hash_manager import HashManager


def validate_hash(hash_value: str, hash_type: str) -> str:
    """
    Validate and normalize a hash value.
    
    Args:
        hash_value: The hash value to validate
        hash_type: The hash type to check against
        
    Returns:
        Normalized hash value
    """
    # Remove any whitespace and convert to lowercase
    normalized = hash_value.strip().lower()
    
    # Check for common hash issues
    expected_length = HashManager.HASH_LENGTHS.get(hash_type, 0)
    
    if expected_length and len(normalized) != expected_length:
        print(f"[!] Warning: Hash value has unexpected length for {hash_type}")
        print(f"    Expected: {expected_length} characters")
        print(f"    Provided: {len(normalized)} characters")
        
        # Try to detect if a prefix or suffix is missing
        if len(normalized) < expected_length:
            missing = expected_length - len(normalized)
            print(f"    Missing: {missing} characters")
            
            # For small missing parts, try to pad with zeros
            if missing <= 8:
                adjusted = normalized.zfill(expected_length)
                print(f"[*] Adjusted hash value: {adjusted}")
                print(f"    (Added {missing} leading zeros)")
                return adjusted
    
    return normalized


def main():
    """
    Main function to process arguments and execute the password cracking strategy.
    """
    # Print banner
    print_banner()
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Validate and normalize the hash value
    args.hashvalue = validate_hash(args.hashvalue, args.hash)
    
    # Check dictionary file size if dictionary attack
    if args.attack == "dictionary":
        dict_info = get_dictionary_info(args.dictionary)
        if dict_info['exists']:
            print(f"[*] Dictionary file size: {dict_info['size_readable']}")
            
            # Adjust settings for large dictionaries
            if dict_info['size_bytes'] > 50 * 1024 * 1024:  # 50 MB
                print(f"[*] Large dictionary detected. Using optimized settings.")
                
                # Increase chunk size for better efficiency
                if args.chunk_size < 50000:
                    adjusted_chunk_size = min(50000, args.chunk_size * 2)
                    print(f"[*] Adjusted chunk size: {adjusted_chunk_size}")
                    args.chunk_size = adjusted_chunk_size
    
    # Print summary of configuration
    print_summary(args.attack, args.hash, args.dictionary, args.threads)
    
    # Initialize performance tracker
    tracker = PerformanceTracker()
    tracker.start()
    
    try:
        # Get the appropriate strategy based on the attack type
        strategy = get_strategy(args)
        
        # Set a checkpoint before running the attack
        tracker.checkpoint("attack_start")
        
        # Run the attack
        result = strategy.execute()
        
        # Stop the timer
        tracker.stop()
        
        # Calculate performance metrics
        elapsed_seconds = tracker.elapsed_seconds()
        passwords_per_second = result.attempts / elapsed_seconds if elapsed_seconds > 0 else 0
        
        # Display results
        print("\n" + "=" * 60)
        if result.success:
            print(f"[+] Password found: \"{result.password}\"")
            print(f"[✓] Crack successful! Time taken: {elapsed_seconds:.2f} seconds")
        else:
            print(f"[-] Password not found. Time taken: {elapsed_seconds:.2f} seconds")
            print(f"[-] Tried {result.attempts:,} combinations")
        
        print(f"[*] Performance: {passwords_per_second:.2f} passwords/second")
        
        # Show detailed stats if requested
        if args.stats:
            print("\n[*] Detailed Statistics:")
            print(f"    Total Attempts: {result.attempts:,}")
            print(f"    Thread Count: {args.threads}")
            
            if 'elapsed_time' in result.details:
                print(f"    Elapsed Time: {result.details['elapsed_time']:.2f} seconds")
            
            if 'words_processed' in result.details:
                print(f"    Words Processed: {result.details['words_processed']:,}")
            
            # Add additional stats based on the attack type
            if args.attack == "dictionary":
                print(f"    Dictionary: {args.dictionary}")
                print(f"    Quick Mode: {'Enabled' if args.quick_mode else 'Disabled'}")
                print(f"    Transformations: {'Enabled' if args.transformations else 'Disabled'}")
                
                # Show stage information if available
                if 'stages' in result.details:
                    stages = result.details['stages']
                    if 'stages' in stages:
                        print("\n    Attack Stages:")
                        for i, stage in enumerate(stages['stages']):
                            if stage['completed']:
                                duration = stage['end_time'] - stage['start_time']
                                print(f"      {i+1}. {stage['description']}: "
                                     f"{stage['attempts']:,} attempts in {duration:.2f}s")
                
                # Show if was found as a common password
                if 'common_password' in result.details and result.details['common_password']:
                    print(f"    Found In: Common password list (very fast match)")
                    
        print("=" * 60)
    
    except KeyboardInterrupt:
        tracker.stop()
        print("\n[!] Operation cancelled by user")
        print(f"[!] Elapsed time: {tracker.elapsed_seconds():.2f} seconds")
        return 1
    except ValueError as e:
        tracker.stop()
        print(f"\n[!] Value Error: {e}")
        if "hash value" in str(e).lower():
            print(f"[!] Please check that your hash value is correct and complete.")
        return 1
    except Exception as e:
        tracker.stop()
        print(f"\n[!] Error: {e}")
        return 1
    
    return 0 if result.success else 1


if __name__ == "__main__":
    sys.exit(main())