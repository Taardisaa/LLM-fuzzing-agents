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

def reply_corpus(fuzzer_name: str, corpus_path: str, timeout: int = 100) -> Optional[int]:
    """
    Run fuzzer and extract edge coverage.
    """
    try:
        # Construct command with optional merge flag

        cmd = [f"./{fuzzer_name}", "-runs=1", f"-timeout={timeout}"]
        cmd.append(corpus_path)
        
        # Run command and capture output
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout (like 2>&1)
            text=True, 
            timeout=timeout + 10  # Add extra timeout buffer
        )
      
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


def get_function_cov(fuzzer_name: str,  corpus_dir: str) -> tuple[int, bool]:
    """
    Reduce corpus by iteratively halving test cases.
    
    Args:
        fuzzer_name: Path to fuzzer binary
        corpus_dir: Path to corpus directory
        function_name: Target function to check coverage
    
    Returns:
        Boolean indicating successful reduction
    """
    import numpy as np

    reply_corpus(fuzzer_name, corpus_dir)

    # list all files in bitmaps directory
    bitmaps_dir = Path("./bitmaps")
    all_maps = sort_files(bitmaps_dir)

    merged_map = np.frombuffer(Path(all_maps[0]).read_bytes(), dtype=np.bool_)
    init_cov = 0
    for counter_map_file in all_maps:
        counter_map = np.frombuffer(Path(counter_map_file).read_bytes(), dtype=np.bool_)

        # only counter once
        if counter_map.sum() != 0 and init_cov == 0:
            init_cov = int(counter_map.sum())
        
        merged_map = merged_map | counter_map
        
    done_cov = int(merged_map.sum())
    
    return init_cov, done_cov


def main():
    """Main script entry point."""
    parser = argparse.ArgumentParser(description='Corpus Reduction Fuzzing Script')
    parser.add_argument('--fuzzer-name', help='Path to fuzzer binary')
    parser.add_argument('--corpus-dir', help='Path to corpus directory')
    
    args = parser.parse_args()
    
    # Set up logging
    global logger
    logger = setup_logging()
    
    # Run corpus reduction
    init_cov, final_cov = get_function_cov(
        args.fuzzer_name, 
        args.corpus_dir, 
    )
    with open("cov.json", "w") as f:
        f.write(json.dumps({"init_cov":init_cov, "final_cov": final_cov}, indent=4))

if __name__ == '__main__':
    main()