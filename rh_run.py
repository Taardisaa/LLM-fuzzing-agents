from agent.eval import run_evaluation
from agent.run_gen import Runner
from bench_cfg import BenchConfig
from pathlib import Path
import sys
import signal
import argparse

from utils.common_utils import register_sigint

def run_gen():
    """
    Run the harness generation process using specified configuration files.
    """
    cfg_list= [
        "/home/ruotoy/Workspace/LLM-fuzzing-agents/cfg/gpt5_mini/gpt5_mini_agent_wild.yaml"
    ]
    for config_path in cfg_list:
        runner = Runner(config_path)
        register_sigint()
        runner.run(multiproc=False)
    return
        
        
def run_eval(proj_name: str="cjson", 
             n_run: int=1, 
             n_partitations: int=1,
             partitation_id: int=0):
    """
    Run the evaluation process for a specified project.
    
    TODO: complete the docstring.
    """
    run_evaluation(output_path=Path(f"/home/ruotoy/Workspace/LLM-fuzzing-agents/outputs_wild/gpt5-mini/agent/{proj_name}"),
                   benchcfg=BenchConfig(f"/home/ruotoy/Workspace/LLM-fuzzing-agents/cfg/gpt5_mini/projects/{proj_name}_eval.yaml"),
                   n_run=n_run, 
                   n_partitations=n_partitations, 
                   partitation_id=partitation_id)
    return


if __name__ == "__main__":
    run_gen()