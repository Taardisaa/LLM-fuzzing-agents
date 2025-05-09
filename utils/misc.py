import os
from matplotlib import pyplot as plt
import io
import yaml
from collections import defaultdict
from constants import PROJECT_PATH, FuzzEntryFunctionMapping,  LanguageType
from langgraph.graph import StateGraph # type: ignore
import re
import random
from typing import DefaultDict, Any
from pathlib import Path

def filter_examples(project_code_usage: list[dict[str, str]], project_lang: LanguageType, usage_token_limit:int=200) -> str:
    filter_code_usage: list[dict[str, str]] = []
    for code in project_code_usage:
        if FuzzEntryFunctionMapping[project_lang] in code["source_code"]:
            continue
        # token limit
        if len(code["source_code"].split()) > usage_token_limit:
            continue
        filter_code_usage.append(code)

    if len(filter_code_usage) == 0:
        function_usage = ""
    else:
        # randomly select one usage
        random_index = random.randint(0, len(filter_code_usage) - 1)
        function_usage = filter_code_usage[random_index]["source_code"]
    
    return function_usage


def extract_name(function_signature: str)-> str:
    # Remove the parameters by splitting at the first '('
    function_name = function_signature.split('(')[0]
    # Split the function signature into tokens to isolate the function name
    tokens = function_name.strip().split()
    assert len(tokens) > 0

    # The function name is the last token, this may include namespaces ::
    function_name = tokens[-1]

    # split the function name by ::
    function_name = function_name.split("::")[-1]

    # remove * from the function name
    if "*" in function_name:
        function_name = function_name.replace("*", "")

    return function_name


def save_code_to_file(code: str, file_path: Path) -> None:
    '''Save the code to the file'''

    dirname = file_path.parent
    if not dirname.exists():
        dirname.mkdir(parents=True, exist_ok=True)

    file_path.write_text(code, encoding="utf-8")


def plot_graph(graph: Any, save_flag: bool = True) -> None: 
    # Assuming graph.get_graph().draw_mermaid_png() returns a PNG image file path
    image_data = graph.get_graph().draw_mermaid_png()

    # Use matplotlib to read and display the image
    img = plt.imread(io.BytesIO(image_data)) # type: ignore
    plt.axis('off')  # type: ignore

    if save_flag:
        plt.savefig("graph.png") # type: ignore
    else:
        plt.imshow(img) # type: ignore
        plt.show()  # type: ignore



def remove_color_characters(text: str) -> str:
      # remove color characters
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)


def load_pormpt_template(template_path: str) -> str:
    '''Load the prompt template'''
    with open(template_path, 'r') as file:
        return file.read()



# def load_model_by_name(model_name: str, temperature: float = 0.7) -> BaseChatModel:
#     '''Load the model by name'''

#     #  obtain environment variables
#     DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")

#     name_vendor_mapping = {
#         "gpt-4o":"openai",
#         "gpt-40-mini":"openai",
#         "gpt-4o-turbo":"openai",
#         "gemini-2.0-flash-exp":  "google",
#         "gemini-1.5-flash": "google",
#         "deepseekv3": "deepseek",
#     }
#     assert model_name in name_vendor_mapping.keys()

#     vendor_name = name_vendor_mapping.get(model_name)
#     if vendor_name == "openai":
#         return ChatOpenAI(model_name, temperature=temperature)
#     elif vendor_name == "deepseek":
#         assert DEEPSEEK_API_KEY is not None
#         return ChatOpenAI(model='deepseek-chat', openai_api_key=DEEPSEEK_API_KEY, openai_api_base='https://api.deepseek.com')
#     elif vendor_name == "anthropic":
#         return ChatAnthropic(model_name, temperature=temperature)
#     elif vendor_name == "google":
#         return ChatGoogleGenerativeAI(model_name, temperature=temperature)
#     else:
#         return None
    

def function_statistics():

    # read benchmark names
    bench_dir = os.path.join(PROJECT_PATH, "benchmark-sets", "all")

    function_list:list[int] = []
    for file in os.listdir(bench_dir):
        # read yaml file
        with open(os.path.join(bench_dir, file), 'r') as f:
            data = yaml.safe_load(f)
            # project_name = data.get("project")
            lang_name = data.get("language")
            # project_harness = data.get("target_path")

            if lang_name not in ["c++", "c"]:
                continue
        
            n_function = len(data.get("functions"))
            function_list.append(n_function)
    print(f"Total number of projects: {len(function_list)}")
   
    total_func = 0
    for i in range(1, 6):
        print(f"{i} of functions in {i} projects: {function_list.count(i)}")
        total_func += i * function_list.count(i)
  
    print(f"Total number of functions: {total_func}")



def project_statistics():

    # read benchmark names
    bench_dir = os.path.join(PROJECT_PATH, "benchmark-sets", "all")

    all_projects: list[tuple[str, str, str]] = []
    for file in os.listdir(bench_dir):
        # read yaml file
        with open(os.path.join(bench_dir, file), 'r') as f:
            data = yaml.safe_load(f)
            project_name = data.get("project")
            lang_name = data.get("language")
            project_harness = data.get("target_path")

            all_projects.append((project_name, lang_name, project_harness))


    # open another file
    build_res_file = os.path.join(PROJECT_PATH, "prompts", "res.txt")

    build_res = {} 
    with open(build_res_file, 'r') as f:
        for line in f:
            project_name, res = line.split(";")
            build_res[project_name] = res

    lang_count: DefaultDict[str, int] = defaultdict(int)

    for project_name, lang_name, project_harness in all_projects:

        if "Error" in build_res[project_name]:
            print(f"{project_name} {build_res[project_name]}")
            # remove from benchmark 
            # file_path = os.path.join(bench_dir, f"{project_name}.yaml")
            # os.remove(file_path)

            continue

        lang_count[lang_name] += 1

    print(lang_count)


def get_benchmark_functions(bench_dir: Path, allowed_projects:list[str] = [], 
                            allowed_langs: list[str]=[], allowed_functions: list[str] = []) -> dict[str, list[str]]:
    """Get all functions from the benchmark directory."""

    allowed_names: list[str] = []
    # not None or empty
    if allowed_functions:
        for function_signature in allowed_functions:
            function_name = extract_name(function_signature)
            allowed_names.append(function_name)
        
    function_dict: dict[str, list[str]] = {}
    # read benchmark names
    all_files = os.listdir(bench_dir)
    all_files.sort()

    for file in all_files:
        # read yaml file
        with open(os.path.join(bench_dir, file), 'r') as f:
            data = yaml.safe_load(f)
            project_name = data.get("project")
            lang_name = data.get("language")

            # only allow specific projects
            if allowed_projects and project_name not in allowed_projects:
                continue
        
            if allowed_langs and lang_name not in allowed_langs:
                continue
        
            function_list: list[str] = []
            for function in data.get("functions"):
                function_signature = function["signature"]
                function_name = extract_name(function_signature)
                
                # screen the function name
                if len(allowed_names) > 0 and function_name not in allowed_names:
                    continue

                function_list.append(function_signature)

            if len(function_list) != 0:
                function_dict[project_name] = function_list
    return function_dict

if __name__ == "__main__":
    function_statistics()