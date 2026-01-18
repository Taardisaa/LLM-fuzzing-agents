from constants import PROJECT_PATH, LanguageType
from pathlib import Path
from typing import Any
import os
import yaml

from utils.proto import PathLike


def PATH_ASSERT(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Path {path} does not exist.")
    

class BenchConfig:
    """
    Configuration class for benchmark settings.

    Attributes:
        oss_fuzz_dir (Path): Path to the OSS-Fuzz directory.
        cache_root (Path): Path to the cache directory.
        benchmark_dir (Path): Path to the benchmark directory. benchmark directory contains
            setting files for each project to be fuzzed, e.g., functions to be fuzzed, paths to harnesses, etc.
        save_root (Path): Path to output directory. It contains results of harness generations.
        model_name (str): Name of the language model to be used.
            Defaults to "gpt-5-mini".
        reasoning (bool): Whether to enable reasoning in the model. Defaults to False.
        temperature (float): Temperature setting for the language model. Defaults to 0

    """
    def __init__(self, config_path: PathLike):
        """Initialize the BenchConfig with configuration from a YAML file.
        Args:
            config_path (PathLike): Path to the YAML configuration file
        """
        self.config = self._load_config(config_path)
        
        # Directory settings
        
        
        oss_fuzz_dir = self.config.get('oss_fuzz_dir')
        if not oss_fuzz_dir:
            raise ValueError("oss_fuzz_dir must be specified in the config file.")
        
        self.oss_fuzz_dir = Path(oss_fuzz_dir).resolve()
        self.cache_root = Path(self.config.get('cache_root', os.path.join(PROJECT_PATH, "cache")))
        self.benchmark_dir = Path(self.config.get('bench_dir', os.path.join(PROJECT_PATH, "benchmark-sets", "ntu")))
        # TODO: I am really confused about this.
        self.save_root = Path(self.config.get('save_root', ""))
        if not self.save_root.is_absolute():
            self.save_root = PROJECT_PATH /  self.save_root
            
        # Added by RH: Reuse built docker containers
        self.existing_docker_name = self.config.get('existing_docker_name', "")

        self.model_name = self.config.get('model_name', "gpt-5-mini")
        self.reasoning = self.config.get('reasoning', False)
        self.temperature = self.config.get('temperature', 0.7)
        self.run_time = self.config.get('run_time', 1)
        self.max_fix = self.config.get('max_fix', 5)
        self.max_tool_call = self.config.get('max_tool_call', 15)
        self.usage_token_limit = self.config.get('usage_token_limit', 1000)
        self.model_token_limit = self.config.get('model_token_limit', 8096)
        self.n_examples = self.config.get('n_examples', 1)
        self.funcs_per_project = self.config.get('funcs_per_project', 1)
        self.example_mode = self.config.get('example_mode', "rank")
        self.example_source = self.config.get('example_source', "project")
        self.iterations = self.config.get('iterations', 3)
        self.num_processes = self.config.get('num_processes', os.cpu_count() // 3) # type: ignore
        self.project_name = self.config.get('project_name', [])
        self.function_signatures = self.config.get('function_signatures', [])
        self.language = LanguageType(self.config.get('language', "CPP"))
        self.fixing_mode = self.config.get('fixing_mode', "issta")

        self.clear_msg_flag = self.config.get('clear_msg_flag', True)
        self.header_mode = self.config.get('header_mode', "agent")
        self.memory_flag = self.config.get('memory_flag', False)
        self.definition_flag = self.config.get('definition_flag', False)
        self.driver_flag = self.config.get('driver_flag', False)
        self.compile_enhance = self.config.get('compile_enhance', False)
        # if True, only use semantic check for evaluation
        self.semantic_mode = self.config.get('semantic_mode', "both")
        self.use_cache_harness_pairs = self.config.get('use_cache_harness_pairs', True)

        # for fuzzing
        self.no_log = self.config.get('no_log', False)
        self.ignore_crashes = self.config.get('ignore_crashes', False)

        # for extracting all functions from project (skip generation)
        self.extract_all_functions = self.config.get('extract_all_functions', False)


    def _load_config(self, config_path: PathLike) -> dict[str, Any]:
        """Load configuration from a YAML file."""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
