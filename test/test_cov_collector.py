from tools.fuzz_tools.cov_collecter import CovCollector
from tools.fuzz_tools.compiler import Compiler
from pathlib import Path
from constants import CompileResults, LanguageType
import random
import shutil
from utils.oss_fuzz_utils import OSSFuzzUtils
from utils.misc import extract_name

def test_one_cov_collector(oss_fuzz_dir: Path, project_name: str, harness_file: Path, function_name: str, corpora_dir: Path):
    
    random_str = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
    new_project_name = "{}_{}".format(project_name, random_str)
    
    scr_path = oss_fuzz_dir / "projects" / project_name
    dst_path = oss_fuzz_dir / "projects" / new_project_name

    oss_tool = OSSFuzzUtils(oss_fuzz_dir, project_name, new_project_name)
    project_fuzzer_name, project_harness_path  = oss_tool.get_harness_and_fuzzer()
    project_lang = oss_tool.get_project_language()

    shutil.copytree(scr_path, dst_path, dirs_exist_ok=True)

    
    harness_code = harness_file.read_text()
    # init the cov collector
    cov_collector = CovCollector(oss_fuzz_dir, project_name, new_project_name, project_lang)
    # collect the coverage
    init_cov, final_cov, chenged = cov_collector.collect_coverage(harness_code, project_harness_path, project_fuzzer_name, function_name, corpora_dir)
    
    cov_collector.clean_workspace()
    # print(f"init_cov: {init_cov} final_cov:{final_cov}, Coverage changed: {chenged}")
    return init_cov, final_cov, chenged


def test_all():
    # 
    OSS_FUZZ_DIR = Path("/home/yk/code/oss-fuzz/")

    res_path = Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_apr7/issta3")

    with open(res_path / "cov.txt", "w") as f:
        sorted_entries = sorted(res_path.iterdir(), key=lambda x: x.name)

        for save_dir in sorted_entries:
            if not save_dir.is_dir():
                continue

            log_file = save_dir / "agent.log"
            log_content = log_file.read_text()

            if "Semantic check passed" in log_content:
                
                # build graph
                PROJECT_NAME = save_dir.name.split("_")[0]
                harness_file = save_dir / "harness.txt"

                function_signature = (save_dir / "function.txt").read_text()
                function_name = extract_name(function_signature)
                corpora_dir = save_dir / "corpora"
                # absolute path

                print(f"Project name: {PROJECT_NAME}, function name: {function_name}", file=f)
                try:
                    init_cov, final_cov,  flag = test_one_cov_collector(OSS_FUZZ_DIR, PROJECT_NAME, harness_file, function_name, corpora_dir)
                    print(f"Init Coverage: {init_cov}, Final Cov:{final_cov}, Coverage changed: {flag}", file=f)
                    f.flush()
                except Exception as e:
                    print(e)
                    continue

def test_single():
    # 
    OSS_FUZZ_DIR = Path("/home/yk/code/oss-fuzz/")

    
    save_dir = Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_apr7/issta1/croaring_roaring_bitmap_portable_deserialize_safe_dxlivceeyjkcsoqn")

    log_file = save_dir / "agent.log"
    log_content = log_file.read_text()
    if "Semantic check passed" in log_content and "Link Error" not in log_content:
        
        # build graph
        PROJECT_NAME = save_dir.name.split("_")[0]
        harness_file = save_dir / "harness.txt"

        function_signature = (save_dir / "function.txt").read_text()
        function_name = extract_name(function_signature)
        corpora_dir = save_dir / "corpora"
        # absolute path

        print(f"Project name: {PROJECT_NAME}, function name: {function_name}")
        try:
            init_cov, final_cov,  flag = test_one_cov_collector(OSS_FUZZ_DIR, PROJECT_NAME, harness_file, function_name, corpora_dir)
            print(f"Init Coverage: {init_cov}, Final Cov:{final_cov}, Coverage changed: {flag}")
        except Exception as e:
            print(e)

if __name__ == "__main__":

    test_all()