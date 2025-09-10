from pathlib import Path
import json
from agent_tools.example_selection import LLMSelector
from utils.misc import get_benchmark_functions, extract_name
import tiktoken
from typing import Any

enc = tiktoken.encoding_for_model("gpt-4o")
def replace_cached_example(cache_dir: Path, bench_dir:Path, llm_name:str = "gpt-4.1"):

    all_functions = get_benchmark_functions(bench_dir, func_per_project=1000)
    
    for project_name in all_functions.keys():
        
        # if project_name not in ["igraph", "bind9"] :
            # continue
# 
        for function_sig in all_functions[project_name]:
            
            function_name = extract_name(function_sig)
            json_file = cache_dir / project_name  / f"{function_name}_references_parser.json"
            save_json_file = cache_dir / project_name / f"{function_name}_references_parser_{llm_name}.json"
            if not json_file.exists():
                print(f"file not exists: {json_file}")
                exit(0)
            if save_json_file.exists():
                continue

            print(f"processing {json_file.name}")
            # Read the JSON file
            with open(json_file, 'r') as f:
                data = f.read()
                json_data = json.loads(data)
            # add new key-value pair to indicate the example 
            llm_selector = LLMSelector(llm_name)
            
            res_list:list[dict[str, Any]] = []            
            for example_json in json_data:
                
                source_code = example_json["source_code"]
                if len(enc.encode(source_code)) > 1000:
                    print(f"source code is too long: {json_file.name}")
                    res_list.append(example_json)
                    continue

                example_json["selection_method"] = llm_selector.name
                example_json["selection_score"] = llm_selector.score_example(
                    function_name,
                    example_json["source_code"]
                )
                res_list.append(example_json)
           
            # Write the modified JSON data back to the file
            with open(save_json_file, 'w') as f:
                json.dump(res_list, f, indent=4)

            # exit(0)
            
if __name__ == "__main__":
    # Example usage
    cache_dir = "/home/yk/code/LLM-reasoning-agents/cache"
    bench_dir = "/home/yk/code/LLM-reasoning-agents/benchmark-sets/ntu/"
    replace_cached_example(Path(cache_dir), Path(bench_dir), llm_name="qwen/qwen3-coder") 