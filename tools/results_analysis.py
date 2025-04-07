import re
import os
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
import yaml
from constants import PROJECT_PATH, LanguageType
from collections import defaultdict
import pickle
import json
from tools.code_tools.parsers.c_parser import CParser

class FuzzResult:
    
    NoLogError = "Log file does not exist"
    HarnessError = "Harness error"
    DOCKERFUZZEREror = "run build_fuzzers first"
    NODETAILSError = "No detailed fuzz log, only 4 lines"
    ABRTERrror = "ABRT"
    FPEError = "FPE"
    STACKOVERFLOWError = "stack-buffer-overflow "
    HEAPBUFFEROVERFLOWError = "heap-buffer-overflow"
    STACKUSEAFTERRETURNError = "stack-use-after-return"
    MemoryLEAKError = "detected memory leaks"
    SEGVError = "SEGV"
    TIMEOUTError = "timeout after"
    TRAGETEXITError = "fuzz target exited"
    ConstantCoverageError = "Constant coverage error"
    MockFunctionError = "Mock function error"
    NoFuzzFunctionError = "No fuzz function error"
    Success = "Success"


    def __init__(self, log_dir, log_name, function_signature=None, harness_path=None):
        self.log_dir = log_dir
        self.log_name = log_name
        self.harness_file = harness_path
        self.function_signature = function_signature if function_signature else self._get_function_signature()

    def _get_function_signature(self):

        # read the function file
        # Regular expression to extract function declarations
        pattern = r"Function:\s([^\(]+\([^\)]+\))"

        # read the function file
        function_file = os.path.join(self.log_dir, "function.txt")
        if os.path.exists(function_file):
            with open(function_file, "r") as f:
                function_signature = f.read()
        else:
            # read log file
            log_file = os.path.join(self.log_dir, "agent.log")
            with open(log_file, "r") as f:
                log_lines = f.read()
            # Extract functions using regex
            try:
                function_signature = re.findall(pattern, log_lines)[0]
            except IndexError:
                function_signature = None

        return function_signature

    def _get_function_name(self, function_signature):
        # Remove the parameters by splitting at the first '('
        function_signature = function_signature.split('(')[0]
        # Split the function signature into tokens to isolate the function name
        tokens = function_signature.strip().split()
        if not tokens:
            return None  # No tokens found; return None
        # The function name is the last token
        last_token = tokens[-1]
        # Remove any namespace qualifiers by splitting on '::'
        function_name = last_token.split('::')[-1]
        return function_name


    def get_fuzz_res(self):
        # check if the output directory exists
        if not os.path.exists(self.log_dir):
            return
        
        # check if the log file exists
        log_file = os.path.join(self.log_dir, self.log_name)
        if not os.path.exists(log_file):
            return FuzzResult.NoLogError
        
        # read the log file
        try:
            with open(log_file, "rb") as f:
                text = f.read()
            text = text.decode("utf-8", errors="replace")
        except Exception as e:
          
            return "Error reading log file"

        # read the harness file
        # harness_file = os.path.join(self.log_dir, "harness.txt")
        assert self.harness_file is not None


        with open(self.harness_file, "r") as f:
            harness_code = f.readlines()

        # check the fuzz function is called
        if self.function_signature is None:
            return "No function name found"
        
        function_name = self._get_function_name(self.function_signature)
        if function_name is None:
            return "No function name found"
        
        #TODO the following may be wrong for strcut function name
        func_count = 0
        for line in harness_code:
            if f"{function_name}(" in line and "// " not in line:
                func_count += 1

            # check if the function is mocked
            if f"{function_name}(" in line and "{" in line:
                return FuzzResult.MockFunctionError
        
        if func_count == 0:
            return FuzzResult.NoFuzzFunctionError

        if FuzzResult.DOCKERFUZZEREror in text:
            return FuzzResult.DOCKERFUZZEREror
        
        if len(text.split("\n")) < 6:
            return FuzzResult.NODETAILSError
        
        # Extract the number after `INITED cov:`
        inited_cov = re.search(r"INITED cov: (\d+)", text)
        inited_cov_value = inited_cov.group(1) if inited_cov else None

        if FuzzResult.ABRTERrror in text:
                return FuzzResult.ABRTERrror
        elif FuzzResult.STACKOVERFLOWError in text:
            return FuzzResult.STACKOVERFLOWError
        elif FuzzResult.HEAPBUFFEROVERFLOWError in text:
            return FuzzResult.HEAPBUFFEROVERFLOWError
        elif FuzzResult.STACKUSEAFTERRETURNError in text:
            return FuzzResult.STACKUSEAFTERRETURNError
        elif FuzzResult.MemoryLEAKError in text:
            return FuzzResult.MemoryLEAKError
        elif FuzzResult.SEGVError in text:
            return FuzzResult.SEGVError
        elif FuzzResult.FPEError in text:
            return FuzzResult.FPEError
        elif FuzzResult.TIMEOUTError in text:
            return FuzzResult.TIMEOUTError
        elif FuzzResult.TRAGETEXITError in text:
            return FuzzResult.TRAGETEXITError
       

        # NO init cov value found
        if inited_cov_value is None:
            return FuzzResult.HarnessError

        # Extract the number after `DONE   cov:`
        done_cov = re.search(r"DONE\s+cov:\s+(\d+)", text)
        done_cov_value = done_cov.group(1) if done_cov else None
        if done_cov_value and  done_cov_value == inited_cov_value:
            return FuzzResult.ConstantCoverageError
        
        # We assume all crash are casues by the harness
        if not done_cov_value:
            return FuzzResult.HarnessError
        # no crash but no coverage increase
        elif done_cov_value == inited_cov_value:
            return FuzzResult.ConstantCoverageError
        
        # no crash and coverage increase, but this may still not be a success
        # elif int(done_cov_value) - int(inited_cov_value) < 20:
            # if strict define success, the done coverage should be greater than inited coverage than a threshold value 
            # done_cov / inited_cov > threshold
            # return FuzzResult.ConstantCoverageError
        else:
            return FuzzResult.Success



def get_function_name(function_signature):
    # Remove the parameters by splitting at the first '('
    function_signature = function_signature.split('(')[0]
    # Split the function signature into tokens to isolate the function name
    tokens = function_signature.strip().split()
    if not tokens:
        return None  # No tokens found; return None
    # The function name is the last token
    last_token = tokens[-1]
    # Remove any namespace qualifiers by splitting on '::'
    function_name = last_token.split('::')[-1]

    if "*" in function_name:
        function_name = function_name.replace("*", "")
    return function_name
    
def run_oss_fuzz_res():

    from constants import PROJECT_PATH
    from collections import defaultdict
    # output_dir = os.path.join(PROJECT_PATH, "outputs_jan_6")
    output_dir =  "/home/yk/code/fuzz-introspector/scripts/oss-fuzz-gen-e2e/workdir/oss-fuzz-gen/results"
    log_name = "/logs/run/"

    res_count = defaultdict(int)

    with open("oss_fuzz_res_true_false.txt", "w") as write_f:
        dir_list = os.listdir(output_dir)
        # sort the directories
        dir_list.sort()
        for dir in dir_list:

            if not os.path.isdir(os.path.join(output_dir, dir)):
                continue

            log_dir = os.path.join(output_dir, dir, "logs", "run")
            all_logs = os.listdir(log_dir)
            all_logs.sort()
            
            if dir == "output-pjsip-pjsip_endpt_send_raw_to_uri":
                print("debug")
            if len(all_logs) > 0:
                log_name = all_logs[-1]
            else:
                log_name = "whatever.log"

            # read the benchmark.yaml file
            with open(os.path.join(output_dir, dir, "benchmark.yaml"), "r") as f:
                bench_data = yaml.safe_load(f)
            function_name = bench_data["functions"][0]["signature"]
           
            #  find the harness file
            harness_dir = os.path.join(output_dir, dir, "fixed_targets")
            for file in os.listdir(harness_dir):
                if os.path.isfile(os.path.join(harness_dir, file)):
                    harness_path = os.path.join(harness_dir, file)
                    break

            assert harness_path is not None

            fuzz_result = FuzzResult(log_dir, log_name, function_name, harness_path)
            res = fuzz_result.get_fuzz_res()
            res_count[res] += 1
            print(f"Log dir: {log_dir}. fuzz res: {res}\n")
            # write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: {res}\n")
            if res == "Success":
                write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: True\n")
            else:
                write_f.write(f"Log dir: {os.path.dirname(os.path.dirname(log_dir))}: False\n")

        total_count = 0
        for key, value in res_count.items():
            total_count += value

        write_f.write(f"Results count: {res_count}")
        write_f.write(f"Total:{total_count}, Success:{res_count['Success'] }, Success rate: {res_count['Success'] / total_count}")



def run_agent_res(output_dir):

    removed_func = ['spdk_json_parse', 'GetINCHIfromINCHI', 'GetINCHIKeyFromINCHI', 'GetStructFromINCHI',
                     'redisFormatCommand', 'stun_is_response', 'bpf_object__open_mem', 'lre_compile', 'JS_Eval', 
                     'dwarf_init_path', 'dwarf_init_b', 'parse_privacy', 'luaL_loadbufferx', 'gf_isom_open_file',
                       'zip_fread', 'dns_name_fromtext', 'dns_message_parse', 'isc_lex_getmastertoken', 
                       'dns_rdata_fromwire', 'dns_name_fromwire', 'dns_master_loadbuffer', 'isc_lex_gettoken', 
                       'dns_message_checksig', 'dns_rdata_fromtext']
    
    kamailio_func = [
	# CodeChecker 15
	"get_src_address_socket",
	"get_src_uri",
	"parse_content_disposition",
	"parse_diversion_header",
	"parse_from_header",
	"parse_from_uri",
	"parse_headers",
	"parse_identityinfo_header",
	"parse_pai_header",
	"parse_privacy",
	"parse_record_route_headers",
	"parse_refer_to_header",
	"parse_route_headers",
	"parse_to_header",
	"parse_to_uri",
    ]

    file_func = ["igraph_edge_connectivity", # F
	"stun_is_response",
	"gdk_pixbuf_animation_new_from_file", # F
	"gdk_pixbuf_new_from_file", # Y
	"gdk_pixbuf_new_from_file_at_scale", # Y
	"gf_isom_open_file",
	"dwarf_init_path",
	"ixmlLoadDocumentEx", #Y
    ]
    # output_dir = os.path.join(PROJECT_PATH, "outputs_jan_6")
    res_count = defaultdict(int)

    total = 0
    success_fsg = []
    success_name = []
    dir_list = os.listdir(output_dir)
        # sort the directories
    dir_list.sort()
    harness_dict = {}
    with open(os.path.join(output_dir, "issta_res_new.txt"), "w") as save_f:

        for dir_name in dir_list:
            if not os.path.isdir(os.path.join(output_dir, dir_name)):
                continue

            work_dir = os.path.join(output_dir, dir_name)

            # read the agent.log
            log_file = os.path.join(work_dir,  "agent.log")
            harness_path = os.path.join(work_dir, "harness.txt")
            func_sig_path = os.path.join(work_dir, "function.txt")

            with open(func_sig_path, "r") as f:
                function_signature = f.read()
                function_name = get_function_name(function_signature)

            #  skip the removed function
            if function_name in removed_func:
                removed_func.remove(function_name)
                continue
            total += 1

            if not os.path.exists(log_file):
                continue
            with open(log_file, "r") as f:
                log_lines = f.read()

            project_name = dir_name.split("_")[0]
            log_prefix = f"{project_name}-{function_name}"
            # log_lines
            no_header_flag = False
            for line in log_lines.split("\n"):
                if "WARNING" in line and "Exit" in line:
                    no_header_flag = True
                    break

            if no_header_flag:
                res_count["NoHeader"] += 1
                # save_f.write(f"Log dir: {log_prefix}. fuzz res: No Header\n")
                continue
        
            # count the no usage case
            # if "Found 0 usage" in log_lines:
                # res_count["NoUsage"] += 1

            if "Fuzz res:No Error" not in log_lines:
                res_count["Fail"] += 1
                # count the no usage case
                # if "Found 0 usage" in log_lines:
                    # res_count["NoUsage"] += 1
                    # save_f.write(f"Log dir: {log_prefix}. fuzz res: Failed, NoUsage\n")
                # else:
                    # save_f.write(f"Log dir: {log_prefix}. fuzz res: Failed, HaveUsage\n")
                continue
            from pathlib import Path

            if function_name in kamailio_func:
                
                flag = False
                harness_code = Path(harness_path).read_text()
                for line in harness_code.splitlines():
                    if not line.strip().startswith('//'):
                        if not line.strip().startswith('extern'):
                            if 'parse_msg(' in line:
                                flag = True
                if not flag:
                    save_f.write(f"Log dir: {log_prefix}. fuzz res: No call for parse msg\n")
                    continue

            parser = CParser(file_path=harness_path, project_lang=LanguageType.C)

            if parser.exist_function_definition(function_name):
                res_count["Fake"] += 1
                # save_f.write(f"Log dir: {log_prefix}. fuzz res: Fake Definition\n")
                continue
            
            if parser.is_fuzz_function_called(function_name):
                res_count["Success"] += 1

                harness_dict[function_name] = harness_path

                if "Found 0 usage" in log_lines:
            #   
                    save_f.write(f"Log dir: {log_prefix}. fuzz res: Success, NoUsage\n")
                else:
                    save_f.write(f"Log dir: {log_prefix}. fuzz res: Success, HaveUsage\n")

                success_fsg.append(function_signature)
                success_name.append(function_name)
                continue
            else:
                res_count["Nocall"] += 1
                # save_f.write(f"Log dir: {log_prefix}. fuzz res: No call\n")
            

        save_f.write(f"Results count: {res_count}")
        save_f.write(f"Total:{total}, Success:{res_count['Success'] }, Success rate: {res_count['Success'] / total}")

    print("remaining func:", removed_func)

    # pickle.dump(success_fsg, open(os.path.join(output_dir, "success_fsg.pkl"), "wb"))
    # pickle.dump(success_name, open(os.path.join(output_dir, "success_name.pkl"), "wb"))
    
    # dump json file

    # with open(os.path.join(output_dir, "harness.json"), "w") as f:
        # json.dump(harness_dict, f)


if __name__ == "__main__":

    run_agent_res("/home/yk/code/LLM-reasoning-agents/outputs/extend/issta3")
    # run_oss_fuzz_res()