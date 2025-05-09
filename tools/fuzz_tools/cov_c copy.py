#!/usr/bin/env python3

import os
import subprocess
import argparse
from typing import List, Optional
import logging
from pathlib import Path
import re
import json
import shutil

def setup_logging():
    """Configure logging for the script."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

def reply_corpus(fuzzer_name: str, corpus_path: str, function_name: str, merge: bool = False, new_corpus_dir: Path=None, timeout: int = 100) -> Optional[int]:
    """
    Run fuzzer and extract edge coverage.
    
    Args:
        fuzzer_name: Path to the fuzzer binary
        corpus_path: Path to the corpus directory
        function_name: Target function to check coverage
        merge: Whether to use merge flag
        timeout: Timeout for fuzzer run
    
    Returns:
        Edge coverage value or None if extraction fails
    """
    try:
        # Construct command with optional merge flag

        cmd = [fuzzer_name, "-print_coverage=1", "-runs=1", f"-timeout={timeout}"]
        
        if merge and new_corpus_dir:
            cmd.append("-merge=1")
            cmd.append(new_corpus_dir)
        
        cmd.append(corpus_path)
        
        # Run command and capture output
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout (like 2>&1)
            text=True, 
            timeout=timeout + 10  # Add extra timeout buffer
        )
        
        # Filter and extract edge coverage,
        # the space before and after function_name is to avoid the case that function_name is a substring of another function name
        coverage_lines = [
            line for line in result.stdout.splitlines() 
            if "COVERED_FUNC" in line and f" {function_name} " in line
        ]
        
        if not coverage_lines:
            logger.warning(f"No coverage information found for {function_name}")
            return None
        if len(coverage_lines) > 1:
            logger.warning(f"Multiple coverage lines found for {function_name}")
            return None
        
        # Extract the two numbers after "edges:"
        matches = re.search(r'edges:\s*(\d+)/(\d+)', coverage_lines[0])

        if matches:
            first_num = matches.group(1)  # '4'
            second_num = matches.group(2) # '4'
            return int(first_num)
        else:
            logger.error("No match")
            return None
    
    except subprocess.TimeoutExpired:
        logger.error(f"Fuzzer command timed out after {timeout} seconds")
        return None
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")
        return None

def sort_files(directory: Path) -> List[Path]:
    """
    Sort the files in a directory.
    
    Args:
        directory: Path to the directory
    
    Returns:
        List of paths to the oldest files
    """
    if not directory.exists():
        raise ValueError(f"Directory does not exist: {directory}")
    
    # Get all files with modification times
    files = [
        (file, file.stat().st_mtime)
        for file in directory.iterdir() 
        if file.is_file()
    ]
    
    # Sort by modification time
    files.sort(key=lambda x: x[1])
    
    return [f[0] for f in files]

def get_function_cov(fuzzer_name: str,  corpus_dir: Path, function_name: str) -> tuple[int, bool]:
    """
    Reduce corpus by iteratively halving test cases.
    
    Args:
        fuzzer_name: Path to fuzzer binary
        corpus_dir: Path to corpus directory
        function_name: Target function to check coverage
    
    Returns:
        Boolean indicating successful reduction
    """
    # create a new corpus directory
    new_corpus_dir = Path(corpus_dir).parent / "new_corpus"
    new_corpus_dir.mkdir(exist_ok=True)

    # Initial run with merge to get baseline
    # with merge flag, the new_corpus_dir will be used as the new corpus directory
    reply_corpus(fuzzer_name, corpus_dir, function_name, merge=True, new_corpus_dir=new_corpus_dir, timeout=100)

    final_edge = reply_corpus(fuzzer_name, new_corpus_dir, function_name, merge=False)
    
    if final_edge is None:
        logger.error("No initial edge coverage found")
        return 0, 0, False
    if final_edge <= 1:
        return 0, final_edge, False

    logger.info(f"Initial edge coverage: {final_edge}")
    
    tmp_corpus_dir = Path(corpus_dir).parent / "tmp_corpus"
    tmp_corpus_dir.mkdir(exist_ok=True)

    # Track number of files
    for oldest_file in sort_files(new_corpus_dir):
        # get oldest half of files
        
        shutil.move(oldest_file, tmp_corpus_dir / oldest_file.name)
      
        # Run fuzzer on temporary corpus
        init_edge = reply_corpus(fuzzer_name, tmp_corpus_dir, function_name)
        
        # If edge changes, stop reduction
        if init_edge >= 1:
            logger.info(f"Edge changed from {init_edge} to {final_edge}. Stopping accumulation.")
            if init_edge < final_edge:
                return init_edge, final_edge, True
            else:
                return init_edge, final_edge, False
        

    return 0, final_edge, False

def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Corpus Reduction Fuzzing Script')
    parser.add_argument('--fuzzer-name', help='Path to fuzzer binary')
    parser.add_argument('--function-name', help='Target function to check coverage')
    parser.add_argument('--corpus-dir', help='Path to corpus directory')
    
    args = parser.parse_args()
    
    # Set up logging
    global logger
    logger = setup_logging()
    
    # Run corpus reduction
    init_cov, final_cov, success = get_function_cov(
        args.fuzzer_name, 
        args.corpus_dir, 
        args.function_name
    )
    
    file_name = f"cov.json"
    with open(os.path.join("/out", file_name), "w") as f:
        f.write(json.dumps({"init_cov":init_cov, "final_cov": final_cov, "changed": success}, indent=4))

if __name__ == '__main__':
    main()