from pathlib import Path
import json
from utils.misc import get_benchmark_functions, extract_name
import tiktoken
from agent_tools.code_search import CodeSearch
from constants import CodeSearchAPIName, LanguageType

enc = tiktoken.encoding_for_model("gpt-4o")
def search_public_example(cache_dir: Path, bench_dir:Path):

    all_functions = get_benchmark_functions(bench_dir, func_per_project=10000)
    
    code_search = CodeSearch(CodeSearchAPIName.Sourcegraph, LanguageType.C)

    for project_name in all_functions.keys():
        
        for function_sig in all_functions[project_name]:
            
            
            function_name = extract_name(function_sig)
            if function_name != "lre_compile":
                continue

            json_file = cache_dir / project_name  / f"{function_name}_references_sourcegraph.json"
            if json_file.exists():
                print(f"file exists: {json_file}")
                continue
            print(f"processing {json_file.name}")


            results = code_search.search(function_name, num_results=0)
            print(f"Found {len(results)} results.")

            # dump the results to json file
            if len(results) > 0:
                json_data = [{"source_code": code} for code in results]
                json_file.parent.mkdir(parents=True, exist_ok=True)
                with open(json_file, "w") as f:
                    json.dump(json_data, f, indent=4)


if __name__ == "__main__":
    cache_dir = Path("/home/yk/code/LLM-reasoning-agents/cache")
    bench_dir = Path("/home/yk/code/LLM-reasoning-agents/benchmark-sets/ntu")
    search_public_example(cache_dir, bench_dir)
    print("Done!")