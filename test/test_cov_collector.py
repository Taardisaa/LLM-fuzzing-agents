from agent_tools.fuzz_tools.cov_collecter import CovCollector
from agent_tools.fuzz_tools.compiler import Compiler
from agent_tools.fuzz_tools.run_fuzzer import FuzzerRunner
from pathlib import Path
from constants import CompileResults
import random
import shutil
from utils.oss_fuzz_utils import OSSFuzzUtils
from utils.misc import extract_name
import os
from multiprocessing import Pool
from typing import Optional, Any

function_harness_mapping = {
"stun_is_binding_response":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"stun_is_command_message":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"stun_is_success_response":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"stun_is_response":("FuzzStunClient", "/src/coturn/fuzzing/FuzzStunClient.c"),
"policydb_read": ("binpolicy-fuzzer","/src/selinux/libsepol/fuzz/binpolicy-fuzzer.c"),
"cil_compile": ("binpolicy-fuzzer","/src/selinux/libsepol/fuzz/binpolicy-fuzzer.c"),
}

def test_one_cov_collector(oss_fuzz_dir: Path, benchmark_dir: Path, project_name: str, harness_file: Path, 
                           function_name: str, corpora_dir: Optional[Path], run_timeout: int = 1) -> tuple[float, float, bool]:
    
    random_str = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=16))
    new_project_name = "{}_{}".format(project_name, random_str)
    
    scr_path = oss_fuzz_dir / "projects" / project_name
    dst_path = oss_fuzz_dir / "projects" / new_project_name

    oss_tool = OSSFuzzUtils(oss_fuzz_dir, benchmark_dir, project_name, new_project_name)
    
    if function_name in function_harness_mapping.keys():
        project_fuzzer_name, project_harness_path = function_harness_mapping[function_name]
    else:
        project_fuzzer_name, project_harness_path  = oss_tool.get_harness_and_fuzzer()

    project_harness_path = Path(project_harness_path)
    project_lang = oss_tool.get_project_language()

    shutil.copytree(scr_path, dst_path, dirs_exist_ok=True)
    harness_code = harness_file.read_text()

    # recomplile the harness code
     # init the compiler
    compiler = Compiler(oss_fuzz_dir, benchmark_dir, project_name, new_project_name)
    # compile the code
    compile_res, build_msg = compiler.compile(harness_code, project_harness_path, project_fuzzer_name)
    if compile_res != CompileResults.Success:
        print(f"Compile error: {build_msg}")
        return 0, 0, False

    # re-run the fuzzer for one hour to see of the coverage changes
    fuzzer = FuzzerRunner(oss_fuzz_dir, new_project_name, project_lang, run_timeout, save_dir=dst_path)
    fuzzer.run_fuzzing(0, project_fuzzer_name)

    if corpora_dir is None:
        corpora_dir = dst_path / "corpora"
    # init the cov collector
    cov_collector = CovCollector(oss_fuzz_dir, benchmark_dir, project_name, new_project_name, project_lang, None)
    # collect the coverage
    init_cov, final_cov, chenged = cov_collector.collect_coverage(harness_code, project_harness_path, project_fuzzer_name, function_name, corpora_dir)
    
    cov_collector.clean_workspace()
    # print(f"init_cov: {init_cov} final_cov:{final_cov}, Coverage changed: {chenged}")
    return init_cov, final_cov, chenged


def test_all(output_dir: str):
    # 
    ossfuzz_dir = Path("/home/yk/code/oss-fuzz/")
    benchmark_dir = Path("/home/yk/code/LLM-reasoning-agents/benchmark-sets/ntu/")

    res_path = Path(output_dir)

    with open(res_path / "cov_1hour.txt", "w") as f:
        sorted_entries = sorted(res_path.iterdir(), key=lambda x: x.name)

        for save_dir in sorted_entries:
            if not save_dir.is_dir():
                continue

            log_file = save_dir / "agent.log"
            log_content = log_file.read_text()

            if "Fuzz res:No Error" in log_content:
                
                # build graph
                project_name = save_dir.name.split("_")[0]
                if project_name == "libpg":
                    project_name = "libpg_query"
                harness_file = save_dir / "harness.txt"

                function_signature = (save_dir / "function.txt").read_text()
                function_name = extract_name(function_signature)
                # corpora_dir = save_dir / "corpora"
                # absolute path
                if function_name != "gdk_pixbuf_animation_new_from_file":
                    continue

                print(f"Project name: {project_name}, function name: {function_name}", file=f)
                try:
                    init_cov, final_cov,  flag = test_one_cov_collector(ossfuzz_dir, benchmark_dir, project_name, harness_file, function_name, corpora_dir=None)
                    print(f"Init Coverage: {init_cov}, Final Cov:{final_cov}, Coverage changed: {flag}", file=f)
                    f.flush()
                except Exception as e:
                    print(e)
                    continue

                exit(0)

def test_all_parallel(output_dir: str):
    # 
    run_timeout = 60
    OSS_FUZZ_DIR = Path("/home/yk/code/oss-fuzz/")
    benchmark_dir = Path("/home/yk/code/LLM-reasoning-agents/benchmark-sets/ntu/")
    res_path = Path(output_dir)

    sorted_entries = sorted(res_path.iterdir(), key=lambda x: x.name)

    task_list: list[tuple[str, Path, str]] = []
    for save_dir in sorted_entries:
        if not save_dir.is_dir():
            continue

        log_file = save_dir / "agent.log"
        log_content = log_file.read_text()

        if "Fuzz res:No Error" in log_content:
            
            # build graph
            project_name = save_dir.name.split("_")[0]
            if project_name == "libpg":
                project_name = "libpg_query"
            harness_file = save_dir / "harness.txt"

            function_signature = (save_dir / "function.txt").read_text()
            function_name = extract_name(function_signature)
            # corpora_dir = save_dir / "corpora"
            # absolute path
            if function_name not in [
                "igraph_edge_connectivity",
                "stun_is_response",
                "gdk_pixbuf_animation_new_from_file",
                "gdk_pixbuf_new_from_file_at_scale",
                "gdk_pixbuf_new_from_file",
                "gf_isom_open_file",
                "dwarf_init_path",
                "ixmlLoadDocumentEx",
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
            ]:
                continue

            task_list.append((project_name, harness_file, function_name))
    
    # os.cpu_count()//2
    with Pool(processes=os.cpu_count()//3) as pool: # type: ignore
        async_results:list[tuple[str, str, Any]] = []
        for project_name, harness_file, function_name in task_list:
        
            # pool.apply(process_project, args=(llm_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call,  cur_save_dir, cache_dir))
            # res = pool.apply(test_one_cov_collector, args=(OSS_FUZZ_DIR, project_name, harness_file, function_name, None, run_timeout))
            res = pool.apply_async(test_one_cov_collector, args=(OSS_FUZZ_DIR, benchmark_dir, project_name, harness_file, function_name, None, run_timeout))
            async_results.append((project_name, function_name, res))

            print(f"Project name: {project_name}, function name: {function_name}")
        pool.close()
        pool.join()

     # Now collect the results and write to file
    with open(res_path / "cov_1hour.txt", "w") as f:
        for project_name, function_name, async_res in async_results:
            try:
                init_cov, final_cov, flag   = async_res.get()
                print(f"Project Name:{project_name}, Function:{function_name}, Init Coverage: {init_cov}, Final Cov:{final_cov}, Coverage changed: {flag}", file=f)
                f.flush()
            except Exception as e:
                f.write(f"{project_name},{function_name}, ERROR: {e}\n")

def test_single():
    # 
    OSS_FUZZ_DIR = Path("/home/yk/code/oss-fuzz/")
    benchmark_dir = Path("/home/yk/code/LLM-reasoning-agents/benchmark-sets/ntu/")    
    save_dir = Path("/home/yk/code/LLM-reasoning-agents/outputs/issta_apr7/issta2/kamailio_parse_identityinfo_header_cfwaszvbjgvxtjyr")
        
    # build graph
    project_name = save_dir.name.split("_")[0]
    if project_name == "libpg":
        project_name = "libpg_query"
    harness_file = save_dir / "harness.txt"

    function_signature = (save_dir / "function.txt").read_text()
    function_name = extract_name(function_signature)
    corpora_dir = save_dir / "corpora"
    # absolute path

    print(f"Project name: {project_name}, function name: {function_name}")
    try:
        init_cov, final_cov,  flag = test_one_cov_collector(OSS_FUZZ_DIR, benchmark_dir, project_name, harness_file, function_name, corpora_dir)
        print(f"Init Coverage: {init_cov}, Final Cov:{final_cov}, Coverage changed: {flag}")
    except Exception as e:
        print(e)

if __name__ == "__main__":

    # test_all(output_dir="/home/yk/code/LLM-reasoning-agents/outputs/issta_apr7/issta1")
    test_all_parallel(output_dir="/home/yk/code/LLM-reasoning-agents/outputs/issta_no_test_apr22/issta2")
    # test_single()
    