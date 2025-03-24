# This  code reimplementation of the algorithm from the ISSTA paper
from typing import Annotated
import subprocess as sp
from langchain_core.messages import ToolMessage
from langchain_openai import ChatOpenAI
from typing_extensions import TypedDict
from langgraph.graph.message import add_messages, MessagesState
import os
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph, START
import random
from constants import LanguageType, CompileResults, PROJECT_PATH, ToolDescMode, FuzzEntryFunctionMapping, LSPResults, Retriever
from pydantic import BaseModel, Field
import logging
import shutil
from langchain_core.tools import tool, BaseTool, StructuredTool
from langgraph.prebuilt import ToolNode
from langchain_anthropic import ChatAnthropic
from multiprocessing import Pool, Lock, Manager
import yaml
import atexit
import asyncio
from prompts.raw_prompts import CODE_FIX_PROMPT, EXTRACT_CODE_PROMPT, CODE_FIX_PROMPT_TOOLS
from utils.misc import plot_graph, load_pormpt_template, save_code_to_file
from tools.code_retriever import CodeRetriever, header_desc_mapping
from tools.code_search import CodeSearch
from agents.reflexion_agent import CodeFormatTool, InitGenerator, FuzzerWraper, CompilerWraper, CodeFixer, AgentFuzzer, FuzzState, CodeAnswerStruct, FixerPromptBuilder
import io
import contextlib
import atexit
import signal
import sys
from tools.fuzzlog_parser import run_agent_res


ISSTA_C_PROMPT = '''
// The following is a fuzz driver written in C language, complete the implementation. Output the continued code in reply only.

// @ examples of API usage
{function_usage}


#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
{header_files}


{function_document}

extern {function_signature};

// the following function fuzzes {function_name}
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
'''

ISSTA_CPP_PROMPT = '''
// The following is a fuzz driver written in C++ language, complete the implementation. Output the continued code in reply only.


// @ examples of API usage 
{function_usage}


#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
{header_files}

{function_document}

extern {function_signature};

// the following function fuzzes {function_name}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
'''

compile_fix_prompt = '''
```
{harness_code}
```

The above {project_lang} code has compilation error.


The error description is: 
{error_msg}

[[SUPPLEMENTAL_INFO]]



Based on the above information, fix the code. Must provide the full fixed code.
'''

fuzz_fix_prompt = '''
```
{harness_code}
```

The above {project_lang} code can be built successfully but has the following errors when runing fuzzer.

{error_msg}

Based on the above information, fix the code. Must provide the full fixed code.

'''

class ISSTAFuzzer(AgentFuzzer):
    def __init__(self, model_name: str, ossfuzz_dir: str, project_name: str, function_signature: str, usage_token_limit: int,
                 run_time: int, max_fix: int, max_tool_call: int, clear_msg_flag:bool, save_dir: str, cache_dir: str):
        super().__init__(model_name, ossfuzz_dir, project_name, function_signature, usage_token_limit, run_time, 
                        max_fix, max_tool_call, clear_msg_flag,  save_dir, cache_dir)


    def build_init_prompt(self, prompt_template):

        # fill the template
        # {function_signature}

        # function_signature = self.function_signature
        

        # {function_name}
        # Remove the parameters by splitting at the first '('
        function_name = self.function_signature.split('(')[0]
        # Split the function signature into tokens to isolate the function name
        tokens = function_name.strip().split()
        assert len(tokens) > 0

        # The function name is the last token, this may include namespaces ::
        function_name = tokens[-1]
        # remove * from the function name
        if "*" in function_name:
            function_name = function_name.replace("*", "")

        # {header_files}
        retriever = CodeRetriever(self.ossfuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.cache_dir , self.logger)
        
        #TODO only include function header may not be enough
        header = retriever.get_symbol_header(function_name)

        if header == LSPResults.NoResult:
            self.logger.warning(f"No header found for {function_name}, Exit")
            self.eailier_stop_flag = True
            return ""

        header = f'#include "{header}"'

        # {function_usage}
        # get the function usage from the project and the public
        # project_code_usage = retriever.get_symbol_references(function_name, retriever=Retriever.LSP)
        project_code_usage = retriever.get_symbol_references(function_name, retriever=Retriever.Parser)

        # filter the usage including the Function entry
        filter_code_usage = []
        for code in project_code_usage:
            if FuzzEntryFunctionMapping[self.project_lang] in code["source_code"]:
                continue
            # token limit
            if len(code["source_code"].split()) > self.usage_token_limit:
                continue
            filter_code_usage.append(code)
        
        self.logger.info(f"Found {len(filter_code_usage)} usage in the project after removing harness.")
        if len(filter_code_usage) == 0:
            function_usage = ""
        else:
            # randomly select one usage
            random_index = random.randint(0, len(filter_code_usage) - 1)
            # random_index = 8
            function_usage = filter_code_usage[random_index]["source_code"]

            #  add comment for function usage
            comment_function_usage = []
            for line in function_usage.split("\n"):
                comment_function_usage.append(f"// {line}")
            function_usage = "\n".join(comment_function_usage)
            self.logger.info(f"Using {random_index}th usage in the project.")
            
        # TODO, no code from public do we need the namespace?
        # code_search = CodeSearch(function_name, self.new_project_name)

        # TODO, no document
        # {function_document}
        function_document = ""

        # {function_signature}
        # function_signature = self.function_signature
        retrieved_signature = retriever.get_symbol_declaration(function_name)
        if len(retrieved_signature) == 0:
            self.logger.warning(f"Can not retrieve signature for {function_name}, use the provided signature from xml")
            function_signature = self.function_signature

        elif len(retrieved_signature) > 1:
            self.logger.warning(f"Multiple signature found for {function_name}, use the provided signature from xml")
            function_signature = self.function_signature
        else:
            function_signature = retrieved_signature[0]["source_code"]
            if function_signature.replace(" ", "").replace("\n", "").replace("\t", "") != self.function_signature.replace(" ", "").replace("\n", "").replace("\t", "")+";":
                self.logger.error(f"Retrieved signature is different from the provided one: {function_signature} vs {self.function_signature}")

        prompt_template = prompt_template.format(header_files=header, function_usage=function_usage, function_document=function_document,
                                             function_signature=function_signature, function_name=function_name)
        prompt_template += "{\n"
        save_code_to_file(prompt_template, os.path.join(self.save_dir, "prompt.txt"))

        return prompt_template

    def build_graph(self):

        llm = ChatOpenAI(model=self.model_name, temperature=0.7)

        code_retriever = CodeRetriever(self.ossfuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.cache_dir, self.logger)
        tools = []
        header_tool = StructuredTool.from_function(
                func=code_retriever.get_symbol_header,
                name="get_symbol_header",
                description=header_desc_mapping[ToolDescMode.Detailed],
            )
        tools.append(header_tool)

        # code formatter
        llm_code_extract = llm.with_structured_output(CodeAnswerStruct)
        code_formater = CodeFormatTool(llm_code_extract, EXTRACT_CODE_PROMPT)


        draft_responder = InitGenerator(llm, self.max_tool_call, continue_flag=True, save_dir=self.save_dir, 
                                        code_callback=code_formater.extract_code, logger=self.logger)

        fixer_llm = llm.bind_tools(tools)

        #  runnable, compile_fix_prompt: str, fuzz_fix_prompt: str, max_tool_call: int, max_fix: int, 
                # clear_msg_flag: bool, save_dir: str, cache_dir: str, code_callback=None , logger=None)
        
        #  compile_fix_prompt: str, fuzz_fix_prompt: str, clear_msg_flag: bool)
        fix_builder = FixerPromptBuilder(compile_fix_prompt, fuzz_fix_prompt,self.project_lang, self.clear_msg_flag)

        code_fixer = CodeFixer(fixer_llm, self.max_fix, self.max_tool_call,  self.save_dir, self.cache_dir,
                                 code_callback=code_formater.extract_code, logger=self.logger)

        fuzzer = FuzzerWraper(self.ossfuzz_dir, self.new_project_name, self.project_lang, 
                             self.run_time,  self.save_dir,  self.logger)
        
        compiler = CompilerWraper(self.ossfuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.harness_pairs, self.save_dir, self.logger)


        # build the graph
        builder = StateGraph(FuzzState)
        # add nodes
        tool_node = ToolNode(tools)

        builder.add_node(self.HarnessGeneratorNode, draft_responder.respond)
        builder.add_node(self.CompilerNode, compiler.compile)
        builder.add_node(self.FixBuilderNode, fix_builder.respond)
        builder.add_node(self.CodeFixerNode, code_fixer.respond)
        builder.add_node(self.FixerToolNode, tool_node)
        builder.add_node(self.FuzzerNode, fuzzer.run_fuzzing)

        # add edges
        builder.add_edge(START, self.HarnessGeneratorNode)
        builder.add_edge(self.HarnessGeneratorNode, self.CompilerNode)
        builder.add_edge(self.FixerToolNode, self.CodeFixerNode)
        builder.add_edge(self.FixBuilderNode, self.CodeFixerNode)

        # add conditional edges
        builder.add_conditional_edges(self.CompilerNode, self.compile_router_mapping,  [self.FixBuilderNode, self.FuzzerNode, END])
        builder.add_conditional_edges(self.CodeFixerNode, self.code_fixer_mapping,  [self.CompilerNode, self.FixerToolNode, END])
        builder.add_conditional_edges(self.FuzzerNode, self.fuzzer_router_mapping, [self.FixBuilderNode, END])

        # the path map is mandatory
        graph = builder.compile()
        return graph


    def run_graph(self, graph):
        if self.eailier_stop_flag:
            return
        
        # read prompt according to the project language (extension of the harness file)
        if self.oss_tool.get_extension() == LanguageType.CPP:
            generator_prompt_temlpate = ISSTA_CPP_PROMPT
        elif self.oss_tool.get_extension() == LanguageType.C:
            generator_prompt_temlpate = ISSTA_C_PROMPT
        else:
            return 
        
        # build the prompt for initial generator
        generator_prompt = self.build_init_prompt(generator_prompt_temlpate)
        if self.eailier_stop_flag:
            return
        
        # plot_graph(graph)
        config = {"configurable": {"thread_id": "1"}, "recursion_limit": 50}
        events = graph.stream(
            {"messages": [("user", generator_prompt)]},
            config,
            stream_mode="values",
        )

        with open(os.path.join(self.save_dir, "output.log"), "w") as f:
            for i, step in enumerate(events):
                f.write(f"Step {i}\n")  # Save step number if needed
                output = io.StringIO()  # Create an in-memory file-like object
                with contextlib.redirect_stdout(output):  # Capture print output
                    step["messages"][-1].pretty_print()
                f.write(output.getvalue() + "\n")  # Write captured output to file

                f.flush()


def process_project(llm_name, ossfuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call, save_dir, cache_dir):


    try:
        agent_fuzzer = ISSTAFuzzer(llm_name, ossfuzz_dir, project_name, function_signature, usage_token_limit=usage_token_limit, run_time=run_time, max_fix=max_fix,
                                    max_tool_call=max_tool_call, clear_msg_flag=True, save_dir=save_dir, cache_dir=cache_dir)
        # Your main logic here
        graph = agent_fuzzer.build_graph()
        agent_fuzzer.run_graph(graph)

    except Exception as e:
        agent_fuzzer.logger.error(f"Exit. An exception occurred: {e}")
        print(f"Program interrupted. from {e} ")
    finally:
        agent_fuzzer.clean_workspace()

import pickle
def get_all_successful_func(save_dir, iteration):
    
    all_success_sig = []
    for i in range(1, iteration):

        res_file = os.path.join(save_dir, f"issta{i}", f"success_fsg.pkl")
        if not os.path.exists(res_file):
            continue
            
        with open(res_file, "rb") as f:
            success_sig = pickle.load(f)
            all_success_sig.extend(success_sig)

    return all_success_sig


def run_parallel(iteration=1):
    # build graph
    ossfuzz_dir = "/home/yk/code/oss-fuzz/"
    # absolute path
    save_dir = os.path.join(PROJECT_PATH, "outputs")
    cur_save_dir = os.path.join(save_dir, f"issta{iteration}")

    cache_dir = "/home/yk/code/LLM-reasoning-agents/cache/"
    llm_name = "gpt-4-0613"
    run_time=0.5
    max_fix=5
    max_tool_call=15
    usage_token_limit = 1000
    function_dict = {}

    all_success_sig = get_all_successful_func(save_dir, iteration)
    # read benchmark names
    bench_dir = os.path.join(PROJECT_PATH, "benchmark-sets", "ntu")
    all_files = os.listdir(bench_dir)

    # sort 
    all_files.sort()

    # resume from project name
    # resume_project_name = "njs.yaml"
    # index = all_files.index(resume_project_name)
    total = 0
    max_num_function = 0
    for file in all_files:
        # read yaml file
        with open(os.path.join(bench_dir, file), 'r') as f:
            data = yaml.safe_load(f)
            project_name = data.get("project")
            lang_name = data.get("language")
            project_harness = data.get("target_path")
            # if project_name not in ["igraph", "liblouis", "libmodbus", "libyang", "lua", "pjsip", "quickjs", "seliux"]:
            # if project_name not in ["coturn", "gdk-pixbuf", "kamilio", "igraph", "liblouis", "libmodbus", "libyang", "lua", "pjsip", "quickjs", "seliux"]:
                # continue

            if lang_name not in ["c++", "c"]:
                continue
        
            function_list = []
            for function in data.get("functions"):
                function_signature = function["signature"].replace("\n", "")
                
                if function_signature in all_success_sig:
                    continue
                
                total += 1
                function_list.append(function_signature)

            # 
            if len(function_list) != 0:
                function_dict[project_name] = function_list
                max_num_function = max(max_num_function, len(function_list))

    print("total projects:", total)
    # os.cpu_count()//2
    with Pool(processes=os.cpu_count()//2) as pool:

        for i in range(max_num_function):
            for key in function_dict.keys():
                if i >= len(function_dict[key]):
                    continue
                function_signature = function_dict[key][i]
                project_name = key
                print(f"{i} of functions in {key}: {len(function_dict[key])}")
                # llm_name, ossfuzz_dir, project_name, function_signature, run_time, max_fix, max_tool_call, save_dir, cache_dir
                # pool.apply(process_project, args=(llm_name, ossfuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call,  cur_save_dir, cache_dir))
                pool.apply_async(process_project, args=(llm_name, ossfuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call,  cur_save_dir, cache_dir))

        pool.close()
        pool.join()

    run_agent_res(cur_save_dir)


def run_single():
      # build graph
    OSS_FUZZ_DIR = "/home/yk/code/oss-fuzz/"
    PROJECT_NAME = "libbpf"

    # absolute path
    SAVE_DIR = "/home/yk/code/LLM-reasoning-agents/outputs/"
    CACHE_DIR = "/home/yk/code/LLM-reasoning-agents/cache/"
    # llm_name = "gpt-4o-mini"
    llm_name = "gpt-4-0613"
    function_signature = r"struct bpf_object * bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz, const struct bpf_object_open_opts *opts)"
    # function_signature = r"int onig_new(regex_t **, const OnigUChar *, const OnigUChar *, OnigOptionType, OnigEncoding, OnigSyntaxType *, OnigErrorInfo *)"

    agent_fuzzer = ISSTAFuzzer(llm_name, OSS_FUZZ_DIR, PROJECT_NAME, function_signature, usage_token_limit = 1000,  run_time=0.5, max_fix=5,
                                max_tool_call=10, clear_msg_flag=True, save_dir=SAVE_DIR, cache_dir=CACHE_DIR)
   
    def signal_handler(sig, frame):
        print(f"Received signal {sig}, cleaning up...")
        agent_fuzzer.clean_workspace()
        sys.exit(0)

    # Register the signal handler for SIGINT (Ctrl+C) and SIGTERM
    signal.signal(signal.SIGINT, signal_handler)

    try:
        graph = agent_fuzzer.build_graph()
        agent_fuzzer.run_graph(graph)
    except Exception as e:
        print(f"An exception occurred: {e}")
    finally:
        agent_fuzzer.clean_workspace()

if __name__ == "__main__":

    # start with 1
    # run_parallel(3)
    run_single()