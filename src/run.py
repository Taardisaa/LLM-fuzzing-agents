import os
import pickle
import signal
import sys
import yaml
from multiprocessing import Pool
from utils.misc import extract_name, get_benchmark_functions
from issta.issta import ISSTAFuzzer
from agent_tools.results_analysis import run_agent_res
from bench_cfg import BenchConfig
import traceback  # Add this at the top

class Runner:
    def __init__(self, benchcfg: BenchConfig):
        """Initialize the Runner with configuration from a BenchConfig object.
        Args:
            benchcfg (BenchConfig): The BenchConfig object containing configuration settings.
        """
        self.config = benchcfg
        
    def get_successful_func(self) -> list[str]:
    
        all_success_sig: list[str] = []
        for i in range(1, self.config.iterations):

            res_file = os.path.join(self.config.save_root, f"success_name_{i}.pkl")
            if not os.path.exists(res_file):
                continue
                
            with open(res_file, "rb") as f:
                success_sig = pickle.load(f)
                all_success_sig.extend(success_sig)

        return all_success_sig


    def filter_functions(self, function_dict: dict[str, list[str]], success_func: list[str]) -> dict[str, list[str]]:
        """Filter out functions that are already successful."""
        for key in function_dict.keys():
            function_list = function_dict[key]
            # filter out the functions that are already successful
            new_function_list: list[str] = []
            for func_sig in function_list:
                function_name = extract_name(func_sig, keep_namespace=True)
                if (function_name not in success_func) and (function_name.lower() not in success_func):
                    new_function_list.append(func_sig)

            function_dict[key] = new_function_list
        return function_dict
    
    def get_num_function(self, function_dict: dict[str, list[str]]) -> tuple[int, int]:
        """Get the maximum number of functions across all projects."""
        total = 0
        max_num_function = 0
        for key in function_dict.keys():
            total += len(function_dict[key])
            if len(function_dict[key]) > max_num_function:
                max_num_function = len(function_dict[key])
        return max_num_function, total

    @staticmethod
    def run_one(config: BenchConfig, function_signature: str, project_name: str, n_run: int=1):
        """Run the fuzzer on a single function."""

        agent_fuzzer = ISSTAFuzzer(config, function_signature, project_name, n_run=n_run)
        try:
        # Your main logic here
            graph = agent_fuzzer.build_graph()
            agent_fuzzer.run_graph(graph)

        except Exception as e:
            agent_fuzzer.logger.error(f"Exit. An exception occurred: {e}")
            traceback.print_exc() 
        finally:
            agent_fuzzer.clean_workspace()
    

    def run_all(self, max_num_function: int, function_dict: dict[str, list[str]], n_run: int=1):
        """Run the fuzzer on all functions in parallel."""

        with Pool(processes=self.config.num_processes) as pool:
            for i in range(max_num_function):
                for key in function_dict.keys():
                    if i >= len(function_dict[key]):
                        continue
                    function_signature = function_dict[key][i]
                    project_name = key
                    print(f"{i+1}th of functions in {key}: {len(function_dict[key])}")
                    
                    pool.apply_async(Runner.run_one, args=(self.config, function_signature, project_name, n_run))
            pool.close()
            pool.join()

    def run(self):
        """Run parallel execution with configuration from YAML file.
        
        Args:
            iterations (int, optional): Number of iterations, uses config value if None
        """
        # copy the config file to the save directory
        if not os.path.exists(self.config.save_root):
            os.makedirs(self.config.save_root)
        config_file = os.path.join(self.config.save_root, "config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump(self.config, f)
        function_dicts = get_benchmark_functions(self.config.bench_dir,
                                                 allowed_projects=[self.config.project_name] if self.config.project_name else [],
                                                 allowed_langs=["c++", "c"],
                                                 allowed_functions=self.config.function_signatures, func_per_project=1000)

       
        for i in range(self.config.iterations):
            iter_res = self.config.save_root / "res_{}.txt".format(i+1)
            if iter_res.exists():
                print(f"Iteration {i+1} already completed. Skipping...")
                continue
            print(f"Running iteration {i+1} of {self.config.iterations}...")
            success_func = self.get_successful_func()
            todo_function_dicts = self.filter_functions(function_dicts, success_func)
            max_num_function, total_function = self.get_num_function(todo_function_dicts)

            if total_function == 0:
                print("All functions are successful. Exiting...")
                break
            print(f"Iteration {i+1} of {self.config.iterations}: {total_function} functions to run")

            # print the function name
            for key in todo_function_dicts.keys():
                print(f"Project: {key}, Number of functions: {len(todo_function_dicts[key])}")
                for func_sig in todo_function_dicts[key]:
                    print(f"  - {extract_name(func_sig, keep_namespace=True)}")

            # print("total Projects: ", len(todo_function_dicts.keys()))
            # print("total functions: ", total_function)
            # max_num_function = 1
            self.run_all(max_num_function, todo_function_dicts, n_run=i+1)

            run_agent_res(self.config.save_root, method="issta", n_run=i+1)

    # def run_single(self):
    #     """Run single execution with configuration from YAML file."""

    #     assert len(self.config.function_signatures) > 0, "No function signatures provided in the config file."
    #     assert self.config.project_name is not None, "No project name provided in the config file."

    #     iterations_list = self.config.get('iterations_list', [1])

    #     for function_signature in self.config.function_signatures:
    #         for i in iterations_list:
    #             Runner.run_one(self.config, function_signature, self.config.project_name, n_run=i)



if __name__ == "__main__":
    # # Check if the script is being run directly
    # if len(sys.argv) < 2:
    #     print("Usage: python run.py <config_path>")
    #     sys.exit(1)

    config_path = "/home/yk/code/LLM-reasoning-agents/cfg/issta_gpt4.yaml"
    bench_cfg = BenchConfig(config_path)
    runner = Runner(bench_cfg)

    # Set up signal handling for graceful termination
    def signal_handler(sig, frame): # type: ignore
        print('Exiting gracefully...')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler) # type: ignore
    
    # Run the main function
    runner.run()