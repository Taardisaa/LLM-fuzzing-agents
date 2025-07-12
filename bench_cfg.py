from constants import PROJECT_PATH
from pathlib import Path
from typing import Any
import os
import yaml


class BenchConfig:
    def __init__(self, config_path: str):
        """Initialize the BenchConfig with configuration from a YAML file.
        Args:
            config_path (str): Path to the YAML configuration file
        """
        self.config = self._load_config(config_path)
        
        # Initialize all parameters as class members with defaults from config
        self.oss_fuzz_dir = Path(self.config.get('oss_fuzz_dir', '/home/yk/code/oss-fuzz/'))
        self.cache_root = Path(self.config.get('cache_root', "/home/yk/code/LLM-reasoning-agents/cache/"))
        self.bench_dir = Path( self.config.get('bench_dir', os.path.join(PROJECT_PATH, "benchmark-sets", "ntu")))
        self.save_root = Path(self.config.get('save_root', ""))

        # absolute path
        if not self.save_root.is_absolute():
            self.save_root = PROJECT_PATH /  self.save_root

        self.model_name = self.config.get('model_name', "gpt-4-0613")
        self.temperature = self.config.get('temperature', 0.7)
        self.run_time = self.config.get('run_time', 1)
        self.max_fix = self.config.get('max_fix', 5)
        self.max_tool_call = self.config.get('max_tool_call', 15)
        self.usage_token_limit = self.config.get('usage_token_limit', 1000)
        self.model_token_limit = self.config.get('model_token_limit', 8096)
        self.n_examples = self.config.get('n_examples', 1)
        self.example_mode = self.config.get('example_mode', "rank")
        self.example_source = self.config.get('example_source', "project")
        self.iterations = self.config.get('iterations', 3)
        self.num_processes = self.config.get('num_processes', os.cpu_count() // 2) # type: ignore
        self.project_name = self.config.get('project_name')
        self.function_signatures = self.config.get('function_signatures', [])

        self.compile_code_info = self.config.get('compile_code_info', False)
        self.fuzz_code_info = self.config.get('fuzz_code_info', False)

        self.clear_msg_flag = self.config.get('clear_msg_flag', True)
        self.tool_flag = self.config.get('tool_flag', False)

    def _load_config(self, config_path: str) -> dict[str, Any]:
        """Load configuration from a YAML file."""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
