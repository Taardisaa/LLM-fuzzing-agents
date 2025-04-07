import os
import subprocess as sp
import re
from tools.fuzz_tools.log_parser import FuzzLogParser
from tools.fuzz_tools.compiler import Compiler
from utils.docker_utils import DockerUtils
from utils.misc import extract_name
from constants import FuzzResult, PROJECT_PATH, CompileResults, COV_WRAP_FILE_NAME, LanguageType
from tools.code_tools.parsers.c_parser import CParser
from tools.code_tools.parsers.java_parser import JavaParser
from pathlib import Path
import json
import shutil


class CovCollector():

    def __init__(self, oss_fuzz_dir: str, project_name: str, new_project_name: str, project_lang: LanguageType):
        
        self.oss_fuzz_dir = oss_fuzz_dir
        self.project_name = project_name
        self.new_project_name = new_project_name      
        self.project_lang = project_lang
        self.docker_utils = DockerUtils(oss_fuzz_dir, project_name, new_project_name, project_lang)
        self.parser = self.get_language_parser()

    def get_language_parser(self):
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            return CParser
        elif self.project_lang == LanguageType.JAVA:
            return JavaParser
        else:
            raise Exception(f"Language {self.project_lang} not supported.")
        
    def gen_wrapped_code(self, harness_code: str, function_name: str) -> str:
        # add the wrapper code to the harness code
        wrap_file = Path(f"{PROJECT_PATH}/tools/fuzz_tools/{COV_WRAP_FILE_NAME}_{self.project_lang.lower()}.txt")
        if not wrap_file.exists():
            print(f"Wrapper file {wrap_file} does not exist")
            return harness_code
        
        wrap_code = wrap_file.read_text()
        # add the wrapper code before the fuzz entry

        # find the fuzz entry
        parser = self.parser(None, harness_code, self.project_lang)
        fuzz_start_row,fuzz_start_col, fuzz_end_row, fuzz_end_col = parser.get_fuzz_function_pos(function_name)
        # add reset_sancov_counters before fuzz function
        lines = harness_code.splitlines()
        
        # TODO: fix indent for python
        indent = " " * fuzz_start_col

        # add save_sancov_counters after fuzz function
        lines.insert(fuzz_end_row + 1, f"{indent}save_sancov_counters();")
        lines.insert(fuzz_start_row, f"{indent}reset_sancov_counters();")

        # insert the wrapper code before the fuzz entry
        row,_, _, _ = parser.get_fuzz_entry_pos()
        lines.insert(row, wrap_code)
        harness_code =  "\n".join(lines)

        return harness_code


    def recompile(self, harness_code,  harness_path, fuzzer_name, function_name) -> bool:
        
        wrapped_code = self.gen_wrapped_code(harness_code, function_name)

        # init the compiler
        compiler = Compiler(self.oss_fuzz_dir, self.project_name, self.new_project_name)
        # compile the code
        compile_res, build_msg = compiler.compile(wrapped_code, harness_path, fuzzer_name)
        if compile_res != CompileResults.Success:
            print(f"Compile error: {build_msg}")
            return False
    
        # run fuzzer driver with testcase
        return True
    

    # ./inchi_input_fuzzer -print_coverage=1 -runs=1  -timeout=100  ./corpora/ 2>&1 | grep inchi_dll.c | grep -w COVERED_FUNC | grep {}
    # ls -ltr
    def collect_coverage(self, harness_code, harness_path, fuzzer_name: str,
                          function_name: str, corpora_dir: Path) -> tuple[int, int, bool]:

        self.recompile(harness_code, harness_path, fuzzer_name, function_name)
        # run the call back
        cmd = ["python", "cov_c.py", "--fuzzer-name", fuzzer_name, 
                "--corpus-dir", "./corpora/"]
        local_out =  Path(self.oss_fuzz_dir) / "build" / "out" / self.new_project_name

        # copy the cov_c.py to the out directory
        shutil.copy(Path(PROJECT_PATH) / "tools" / "fuzz_tools" / "cov_c.py", local_out / "cov_c.py")
        shutil.copy(Path(PROJECT_PATH) / "tools" / "fuzz_tools" / "cov_wrap_code_c.txt", local_out / "cov_wrap_code_c.txt")
        volumes = {local_out: {"bind": "/out", "mode": "rw"},
                   corpora_dir: {"bind": "/out/corpora", "mode": "rw"}}
        
        self.docker_utils.run_cmd(cmd, volumes=volumes, working_dir="/out")

        cov_path = local_out / "cov.json"
        if not cov_path.exists():
            print(f"Coverage file {cov_path} does not exist")
            return 0, False
        
        with open(cov_path, "r") as f:
            cov = json.load(f)
            init_cov, final_cov = cov.get("init_cov", 0), cov.get("final_cov", 0)
            if init_cov != 0 and final_cov > init_cov:
                return init_cov, final_cov, True
            else:
                return init_cov, final_cov, False