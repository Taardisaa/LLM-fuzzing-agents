from tools.fuzz_tools.cov_collecter import CovCollector
from tools.fuzz_tools.compiler import Compiler
from pathlib import Path
from constants import CompileResults, LanguageType
import random
import shutil
from utils.oss_fuzz_utils import OSSFuzzUtils
from utils.misc import extract_name
from issta.semantic_check import SemaCheck
function_harness_mapping = {
"stun_is_binding_response":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"stun_is_command_message":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"stun_is_success_response":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"policydb_read": ("binpolicy-fuzzer","/src/selinux/libsepol/fuzz/binpolicy-fuzzer.c"),
"cil_compile": ("binpolicy-fuzzer","/src/selinux/libsepol/fuzz/binpolicy-fuzzer.c"),
}

def test_one(oss_fuzz_dir: Path, project_name: str, harness_file: Path, function_name: str):
    
    random_str = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
    new_project_name = "{}_{}".format(project_name, random_str)
    
    scr_path = oss_fuzz_dir / "projects" / project_name
    dst_path = oss_fuzz_dir / "projects" / new_project_name

    oss_tool = OSSFuzzUtils(oss_fuzz_dir, project_name, new_project_name)
    
    if function_name in function_harness_mapping.keys():
        project_fuzzer_name, project_harness_path = function_harness_mapping[function_name]
    else:
        project_fuzzer_name, project_harness_path  = oss_tool.get_harness_and_fuzzer()

    shutil.copytree(scr_path, dst_path, dirs_exist_ok=True)
    project_lang = oss_tool.get_project_language()
    checker = SemaCheck(oss_fuzz_dir, project_name, new_project_name, function_name, project_lang)
    res = checker.check(harness_file.read_text(), project_harness_path, project_fuzzer_name)
    checker.clean_workspace()
    # print(f"init_cov: {init_cov} final_cov:{final_cov}, Coverage changed: {chenged}")
    return res 


def test_single(oss_fuzz_dir, save_dir):
    log_file = save_dir / "agent.log"
    log_content = log_file.read_text()

    if "No Error" not  in log_content:
        return False
        
    # build graph
    project_name = save_dir.name.split("_")[0]
    if project_name == "libpg":
        project_name = "libpg_query"
    harness_file = save_dir / "harness.txt"

    function_signature = (save_dir / "function.txt").read_text()
    function_name = extract_name(function_signature)

    try:
        flag = test_one(oss_fuzz_dir, project_name, harness_file, function_name)
        return flag
    except Exception as e:
        print(e)
        return False

def test_all():
    # 
    OSS_FUZZ_DIR = Path("/home/yk/code/oss-fuzz/")

    res_path = Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_no_test_apr22/issta3")

    with open(res_path / "issta_res_check.txt", "w") as f:
        sorted_entries = sorted(res_path.iterdir(), key=lambda x: x.name)

        for save_dir in sorted_entries:
            if not save_dir.is_dir():
                continue

            flag = test_single(OSS_FUZZ_DIR, save_dir)
            print(f"Log dir: {save_dir.name}, Semantic check res: {flag}", file=f)
            f.flush()

if __name__ == "__main__":

    test_all()
    exit(0)
    oss_fuzz_dir = Path("/home/yk/code/oss-fuzz/")
    res_path = Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_no_test_apr22/issta1/civetweb_mg_get_response_xgqerhvrxombkmtf")

    flag = test_single(oss_fuzz_dir, res_path)
    print("Semantic check res: ", flag)