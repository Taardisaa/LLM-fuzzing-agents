from pathlib import Path
import json
from  tools.example_selection import LLMSelector
import tiktoken
from typing import Any

enc = tiktoken.encoding_for_model("gpt-4o")
def replace_cached_example(cache_dir: Path, llm_name:str = "gpt-4"):

    for project_dir in cache_dir.iterdir():
        if not project_dir.is_dir():
            continue
        
        if project_dir.name != "bind9":
            continue

        for json_file in project_dir.iterdir():
            if "references" not in json_file.name:
                continue
            
            # if json_file.name != "gdk_pixbuf_animation_new_from_file_references_parser.json":
                # continue
            print(f"processing {json_file.name}")
            # Read the JSON file
            with open(json_file, 'r') as f:
                data = f.read()
                json_data = json.loads(data)
            # add new key-value pair to indicate the example 

            function_list = json_file.name.split("_")[:-2]
            function_name = "_".join(function_list)
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

            with open(json_file, 'w') as f:
                json.dump(res_list, f, indent=4)

            # exit(0)
            
if __name__ == "__main__":
    # Example usage
    cache_dir = "/home/yk/code/LLM-reasoning-agents/cache"
    replace_cached_example(Path(cache_dir), llm_name="gpt-4-0613") 