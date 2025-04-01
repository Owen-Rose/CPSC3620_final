"""
CLI Module - Command-line Interface Handler

This module handles parsing command-line arguments and provides
configuration for the advanced password cracking tool.
"""

import argparse
import os
import multiprocessing
import textwrap
from typing import Dict, Any, NamedTuple, List


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments for the advanced password cracking tool.
    
    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    # Get the default number of CPU cores
    default_threads = min(8, multiprocessing.cpu_count())
    
    parser = argparse.ArgumentParser(
        description="Advanced Password Cracking Tool for Algorithm Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''
        Examples:
          python main.py --attack dictionary --hash md5 --hashvalue 5f4dcc3b5aa765d61d8327deb882cf99 --dictionary wordlist.txt
          python main.py --attack pattern --hash md5 --hashvalue 5f4dcc3b5aa765d61d8327deb882cf99 --dictionary rockyou.txt
          python main.py --attack brute_force --hash md5 --hashvalue 5f4dcc3b5aa765d61d8327deb882cf99 --charset lower+digits
        ''')
    )

    # Required arguments
    parser.add_argument("--attack", required=True, choices=["dictionary", "pattern", "brute_force"],
                        help="Type of attack to perform")
    parser.add_argument("--hash", required=True, choices=["md5", "sha1", "sha256"],
                        help="Hashing algorithm used")
    parser.add_argument("--hashvalue", required=True,
                        help="Hash value to crack")

    # Dictionary attack specific arguments
    parser.add_argument("--dictionary", required=False,
                        help="Path to dictionary file for dictionary attack")
    parser.add_argument("--chunk-size", type=int, default=25000,
                        help="Number of words to process in one chunk (for large dictionaries)")
    parser.add_argument("--quick-mode", action="store_true", default=True,
                        help="Enable quick mode: check words without transformations first")
    parser.add_argument("--no-quick-mode", action="store_false", dest="quick_mode",
                        help="Disable quick mode")
    
    # Performance options
    parser.add_argument("--threads", "-t", type=int, default=default_threads,
                        help=f"Number of threads to use (default: {default_threads})")
    parser.add_argument("--transformations", action="store_true", default=True,
                        help="Apply common transformations to dictionary words")
    parser.add_argument("--no-transformations", action="store_false", dest="transformations",
                        help="Disable word transformations")
    parser.add_argument("--max-transformations", type=int, default=15,
                        help="Maximum number of transformations to apply per word")
    
    # Advanced options
    parser.add_argument("--advanced-mode", action="store_true", default=True,
                        help="Enable advanced pattern-based transformations")
    parser.add_argument("--no-advanced-mode", action="store_false", dest="advanced_mode",
                        help="Disable advanced transformations")
    parser.add_argument("--prioritize-common", action="store_true", default=True,
                        help="Prioritize common passwords first")
    parser.add_argument("--prioritize-length", action="store_true", default=True,
                        help="Prioritize words by length (favors 4-10 characters)")
    
    # Pattern selection option - renamed to avoid conflict
    parser.add_argument("--pattern-type", 
                      choices=["leet", "keyboard", "common_words", "year_patterns", "special_char"],
                      help="Specify target pattern type (for pattern attack)")
    
    # Output options
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--output", "-o",
                        help="Save results to output file")
    parser.add_argument("--stats", action="store_true", default=True,
                        help="Show detailed statistics after completion")
    parser.add_argument("--no-stats", action="store_false", dest="stats",
                        help="Hide detailed statistics")
    parser.add_argument("--check-hash", action="store_true", default=True,
                        help="Check hash format and correct if needed")
    parser.add_argument("--no-check-hash", action="store_false", dest="check_hash",
                        help="Do not check hash format")
    
    # Demo mode and visualization options
    parser.add_argument("--demo-mode", action="store_true",
                        help="Enable demonstration mode with visual enhancements")
    parser.add_argument("--max-attempts", type=int, default=10000,
                        help="Maximum number of password attempts")
    parser.add_argument("--show-progress", action="store_true", default=True,
                        help="Show progress bar")
    parser.add_argument("--no-progress", action="store_false", dest="show_progress",
                        help="Hide progress bar")
    
    # Brute force specific options
    parser.add_argument("--min-length", type=int, default=1,
                      help="Minimum password length for brute force attack")
    parser.add_argument("--max-length", type=int, default=5,
                      help="Maximum password length for brute force attack")
    parser.add_argument("--charset", default="lower+digits",
                      choices=["lower", "upper", "digits", "special", "lower+digits", 
                              "lower+upper", "lower+upper+digits", "all"],
                      help="Character set to use for brute force attack")
    parser.add_argument("--custom-charset", 
                      help="Custom character set (overrides --charset)")

    args = parser.parse_args()

    # Validate arguments based on attack type
    if args.attack == "dictionary" and not args.dictionary:
        parser.error("--dictionary is required for dictionary attack")
    
    # Validate dictionary file exists if specified
    if args.dictionary and not os.path.isfile(args.dictionary):
        parser.error(f"Dictionary file not found: {args.dictionary}")
    
    # Validate thread count
    if args.threads < 1:
        parser.error("Thread count must be at least 1")
    elif args.threads > multiprocessing.cpu_count() * 2:
        print(f"[!] Warning: Thread count ({args.threads}) exceeds recommendations")
    
    # Check chunk size
    if args.chunk_size < 100:
        parser.error("Chunk size must be at least 100")
    elif args.chunk_size > 1000000:
        print(f"[!] Warning: Very large chunk size may impact memory usage")
    
    # Warn about max transformations
    if args.max_transformations > 25:
        print(f"[!] Warning: High transformation count ({args.max_transformations}) will significantly increase processing time")

    # Validate brute force options
    if args.attack == "brute_force":
        if args.max_length > 8:
            print(f"[!] Warning: Brute force with max length {args.max_length} may take a very long time")
        if args.min_length < 1:
            parser.error("Minimum length must be at least 1")
        if args.min_length > args.max_length:
            parser.error("Minimum length cannot be greater than maximum length")

    return args


def get_attack_config(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Extract attack-specific configuration from parsed arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        Dictionary containing attack configuration parameters.
    """
    config = {
        'hash_type': args.hash,
        'hash_value': args.hashvalue,
        'verbose': args.verbose,
        'threads': args.threads,
        'transformations': args.transformations,
        'show_stats': args.stats,
        'max_transformations': args.max_transformations,
        'check_hash': args.check_hash,
        'advanced_mode': args.advanced_mode,
        'prioritize_common': args.prioritize_common,
        'prioritize_length': args.prioritize_length,
        'demo_mode': args.demo_mode if hasattr(args, 'demo_mode') else False,
        'max_attempts': args.max_attempts if hasattr(args, 'max_attempts') else 10000,
        'show_progress': args.show_progress if hasattr(args, 'show_progress') else True,
    }
    
    # Add pattern type if specified using the renamed argument
    if hasattr(args, 'pattern_type') and args.pattern_type:
        config['target_pattern'] = args.pattern_type
    
    # Add attack-specific parameters
    if args.attack == "dictionary":
        config['dictionary_path'] = args.dictionary
        config['chunk_size'] = args.chunk_size
        config['quick_mode'] = args.quick_mode
    
    # Add brute force specific parameters
    if args.attack == "brute_force":
        config['min_length'] = args.min_length
        config['max_length'] = args.max_length
        config['charset'] = args.charset
        if hasattr(args, 'custom_charset') and args.custom_charset:
            config['custom_charset'] = args.custom_charset
    
    # Add output file if specified
    if args.output:
        config['output_path'] = args.output
    
    return config


def print_banner() -> None:
    """
    Print a banner for the password cracking tool.
    """
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║  Advanced Password Cracker                            ║
    ║  Optimized for Complex Password Analysis              ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)


def print_summary(attack_type: str, hash_type: str, wordlist: str, threads: int) -> None:
    """
    Print a summary of the cracking configuration.
    
    Args:
        attack_type: Type of attack
        hash_type: Type of hash algorithm
        wordlist: Path to wordlist (if applicable)
        threads: Number of threads
    """
    print("\n[*] Configuration Summary:")
    print(f"    Attack Type: {attack_type}")
    print(f"    Hash Algorithm: {hash_type}")
    
    if wordlist and attack_type == "dictionary":
        print(f"    Wordlist: {wordlist}")
    elif attack_type == "pattern":
        print(f"    Pattern-based attack: Using rule transformations")
    elif attack_type == "brute_force":
        print(f"    Brute force attack: Using BFS approach")
        
    print(f"    Threads: {threads}")
    print()


def get_dictionary_info(path: str) -> Dict[str, Any]:
    """
    Get information about a dictionary file.
    
    Args:
        path: Path to the dictionary file
        
    Returns:
        Dictionary containing file information
    """
    if not path or not os.path.isfile(path):
        return {
            'exists': False,
            'size_bytes': 0,
            'size_readable': '0 B'
        }
    
    size_bytes = os.path.getsize(path)
    
    # Convert to readable size
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size_readable = size_bytes
    unit_index = 0
    
    while size_readable > 1024 and unit_index < len(units) - 1:
        size_readable /= 1024
        unit_index += 1
    
    return {
        'exists': True,
        'size_bytes': size_bytes,
        'size_readable': f"{size_readable:.2f} {units[unit_index]}"
    }