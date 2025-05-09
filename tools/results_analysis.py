import os
from constants import LanguageType
from collections import defaultdict
import pickle
from tools.code_tools.parsers.c_cpp_parser import CCPPParser
from utils.misc import extract_name
from pathlib import Path
from typing import DefaultDict

removed_func = ['spdk_json_parse', 'GetINCHIfromINCHI', 'GetINCHIKeyFromINCHI', 'GetStructFromINCHI',
                    'redisFormatCommand', 'stun_is_response', 'bpf_object__open_mem', 'lre_compile', 'JS_Eval', 
                    'dwarf_init_path', 'dwarf_init_b', 'parse_privacy', 'luaL_loadbufferx', 'gf_isom_open_file',
                    'zip_fread', 'dns_name_fromtext', 'dns_message_parse', 'isc_lex_getmastertoken', 
                    'dns_rdata_fromwire', 'dns_name_fromwire', 'dns_master_loadbuffer', 'isc_lex_gettoken', 
                    'dns_message_checksig', 'dns_rdata_fromtext']
    

class FuzzResult:
    
    NoLogError = "Log file does not exist"
    NoHeader = "No Header Found"
    Failed = "Failed"
    Success = "Success"
    NoCall = "No call"
    Fake = "Fake Definition"


# def run_oss_fuzz_res():

#     from collections import defaultdict
#     output_dir =  Path( "/home/yk/code/fuzz-introspector/scripts/oss-fuzz-gen-e2e/workdir/oss-fuzz-gen/results")
#     log_name = "/logs/run/"

#     res_count: DefaultDict[str, int] = defaultdict(int)

#     with open("oss_fuzz_res_true_false.txt", "w") as write_f:
#         dir_list = os.listdir(output_dir)
#         # sort the directories
#         dir_list.sort()
#         for dir in dir_list:

#             if not os.path.isdir(os.path.join(output_dir, dir)):
#                 continue

#             log_dir = os.path.join(output_dir, dir, "logs", "run")
#             all_logs = os.listdir(log_dir)
#             all_logs.sort()
            
#             if len(all_logs) > 0:
#                 log_name = all_logs[-1]
#             else:
#                 log_name = "whatever.log"

#             # read the benchmark.yaml file
#             with open(os.path.join(output_dir, dir, "benchmark.yaml"), "r") as f:
#                 bench_data = yaml.safe_load(f)
#             function_name = bench_data["functions"][0]["signature"]
           
#             #  find the harness file
#             harness_path = None
#             harness_dir = os.path.join(output_dir, dir, "fixed_targets")
#             for file in os.listdir(harness_dir):
#                 if os.path.isfile(os.path.join(harness_dir, file)):
#                     harness_path = os.path.join(harness_dir, file)
#                     break
                    
#             assert harness_path is not None

#             fuzz_result = FuzzResult(log_dir, log_name, function_name, harness_path)
#             res = fuzz_result.get_fuzz_res()
#             res_count[res] += 1
#             print(f"Log dir: {log_dir}. fuzz res: {res}\n")
#             # write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: {res}\n")
#             if res == "Success":
#                 write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: True\n")
#             else:
#                 write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: False\n")

#         total_count = 0
#         for key, value in res_count.items():
#             total_count += value

#         write_f.write(f"Results count: {res_count}")
#         write_f.write(f"Total:{total_count}, Success:{res_count['Success'] }, Success rate: {res_count['Success'] / total_count}")


def get_run_res(work_dir: Path, method: str="issta"):

    work_dir = Path(work_dir)
      # read the agent.log
    log_file = work_dir / "agent.log"
    harness_path = work_dir / "harness.txt"
    func_sig_path = work_dir / "function.txt"

    function_signature = func_sig_path.read_text()
    function_name = extract_name(function_signature)

    if not log_file.exists():
        return FuzzResult.NoLogError, False
    
    log_lines = log_file.read_text()
   
    # count the no usage case
    if "Found 0 usage" in log_lines:
        usage_flag = False
    else:
        usage_flag = True

    for line in log_lines.split("\n"):
        if "WARNING" in line and "Exit" in line:
            return FuzzResult.NoLogError, usage_flag

    # for issta
    if method == "issta":
        pass_pattern = "Semantic check passed"
    else:
        pass_pattern = "Fuzz res:No Error"
        
    if pass_pattern not in log_lines:
        return FuzzResult.Failed, usage_flag

    parser = CCPPParser(file_path=harness_path, project_lang=LanguageType.C)

    if parser.exist_function_definition(function_name):
        return FuzzResult.Fake, usage_flag
    
    if parser.is_fuzz_function_called(function_name):
        return FuzzResult.Success, usage_flag
    else:
        return FuzzResult.NoCall, usage_flag
 

def run_old_agent_res(output_dir: Path, method: str="issta"):


    res_count: DefaultDict[str, int] = defaultdict(int)

    total = 0
    success_name: list[str] = []
    with open(os.path.join(output_dir, "issta_res.txt"), "w") as save_f:

        for work_dir in output_dir.iterdir():
            if not work_dir.is_dir():
                continue

            func_sig_file = work_dir / "function.txt"

            function_signature = func_sig_file.read_text()
            function_name = extract_name(function_signature)

            project_name = work_dir.name.split("_")[0]
        
            total += 1
            fuzz_res, usage_falg = get_run_res(work_dir, method=method)
            res_count[fuzz_res] += 1

            if usage_falg:
                save_f.write(f"{project_name}/{function_name}. fuzz res: {fuzz_res}, HaveUsage\n")
            else:
                save_f.write(f"{project_name}/{function_name}. fuzz res: {fuzz_res}, NoUsage\n")
          
            if fuzz_res == FuzzResult.Success:
                success_name.append(function_name)
        
        save_f.write(f"Results count: {res_count}")
        save_f.write(f"Total:{total}, Success:{res_count['Success'] }, Success rate: {res_count['Success'] / total}")

    pickle.dump(success_name, open(os.path.join(output_dir, "success_name.pkl"), "wb"))



def run_agent_res(output_path: Path, method:str="issta", n_run:int=1):

    res_count: DefaultDict[str, int] = defaultdict(int)
    output_path = Path(output_path)
    success_name_list:list[str] = []

    res_file = output_path / f"res_{n_run}.txt"
    # with open(res_file, "w") as save_f:
    
    all_path:list[tuple[str, str, Path]] = []
    for project_path in output_path.iterdir():
        if not project_path.is_dir():
            continue

        for function_path in project_path.iterdir():
            if not function_path.is_dir():
                continue

            for work_dir in function_path.iterdir():
                if not work_dir.is_dir():
                    continue
                if not work_dir.exists():
                    continue
                # check if the directory is empty
                if len(os.listdir(work_dir)) == 0:
                    continue
                
                all_path.append((project_path.name, function_path.name, work_dir))
        
    with open(res_file, "w") as save_f:
        for project_name, function_name, work_dir in all_path:
            fuzz_res, usage_falg = get_run_res(work_dir, method=method)
            res_count[fuzz_res] += 1

            if usage_falg:
                save_f.write(f"{project_name}/{function_name}. fuzz res: {fuzz_res}, HaveUsage\n")
            else:
                save_f.write(f"{project_name}/{function_name}. fuzz res: {fuzz_res}, NoUsage\n")
                
            if fuzz_res == FuzzResult.Success:
                success_name_list.append(function_name)
            
        save_f.write(f"Results count: {res_count}\n")
        save_f.write(f"Success:{res_count['Success'] }")

    pickle.dump(success_name_list, open(os.path.join(output_path, f"success_name_{n_run}.pkl"), "wb"))


if __name__ == "__main__":

    run_agent_res(Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_rank_one"), method="issta")
    # run_oss_fuzz_res()