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
from constants import LanguageType, CompileResults, PROJECT_PATH, ToolDescMode, FuzzEntryFunctionMapping, LSPResults, Retriever, FuzzResult
from langchain_core.tools import tool, BaseTool, StructuredTool
from langgraph.prebuilt import ToolNode
from langchain_anthropic import ChatAnthropic
import yaml
from prompts.raw_prompts import CODE_FIX_PROMPT, EXTRACT_CODE_PROMPT
from utils.misc import plot_graph, load_pormpt_template, save_code_to_file, filter_examples, extract_name
from tools.code_retriever import CodeRetriever, header_desc_mapping
from agents.reflexion_agent import CodeFormatTool, InitGenerator, FuzzerWraper, CompilerWraper, CodeFixer, AgentFuzzer, FuzzState, CodeAnswerStruct
import io
import contextlib
import signal
import sys
from tools.results_analysis import run_agent_res
from multiprocessing import Pool
import logging
from issta.semantic_check import SemaCheck
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


REMOVED_FUNC = ['spdk_json_parse', 'GetINCHIfromINCHI', 'GetINCHIKeyFromINCHI', 'GetStructFromINCHI',
                'redisFormatCommand', 'stun_is_response', 'bpf_object__open_mem', 'lre_compile', 'JS_Eval', 
                'dwarf_init_path', 'dwarf_init_b', 'parse_privacy', 'luaL_loadbufferx', 'gf_isom_open_file',
                'zip_fread', 'dns_name_fromtext', 'dns_message_parse', 'isc_lex_getmastertoken', 
                'dns_rdata_fromwire', 'dns_name_fromwire', 'dns_master_loadbuffer', 'isc_lex_gettoken', 
                'dns_message_checksig', 'dns_rdata_fromtext']

class FixerPromptBuilder:
    def __init__(self, oss_fuzz_dir: str,  project_name: str, new_project_name: str, cache_dir: str , usage_token_limit: int, logger: logging.Logger,
                 compile_fix_prompt: str, fuzz_fix_prompt: str, project_lang: LanguageType, clear_msg_flag: bool):
        
        self.oss_fuzz_dir = oss_fuzz_dir
        self.new_project_name = new_project_name
        self.project_name = project_name
        self.cache_dir = cache_dir
        self.logger = logger
        self.usage_token_limit = usage_token_limit

        self.compile_fix_prompt = compile_fix_prompt
        self.fuzz_fix_prompt = fuzz_fix_prompt
        self.project_lang = project_lang
        self.clear_msg_flag = clear_msg_flag

    def build_compile_prompt(self, harness_code, error_msg):
        '''
        Build the prompt for the code fixer. If you need to customize the prompt, you can override this function.
        '''
        return self.compile_fix_prompt.format(harness_code=harness_code, error_msg=error_msg, project_lang=self.project_lang)

    def build_fuzz_prompt(self, harness_code, error_msg):
        '''
        Build the prompt for the code fixer. If you need to customize the prompt, you can override this function.
        '''
        # extract 
        #1 0x5639df576b54 in ixmlDocument_createAttributeEx /src/pupnp/ixml/src/document.c:269:26
        reversed_stack = error_msg.split("\n")[::-1]
        index = None
        for i, line in enumerate(reversed_stack):
            if not line.strip().startswith("#"):
                continue
            # find the first api of the project in stack trace
            if "LLVMFuzzerTestOneInput" in line:
                index = i
                break
        
        if index and index+1 < len(reversed_stack):
            crash_line = reversed_stack[index+1]

            row_data = crash_line.strip().split(" ")

            # 5 for C
            if len(row_data) != 5:
                self.logger.info(f"Error message format is not correct: {line}")
            else:
                _, _, _, func_name, file_path = row_data
                
                retriever = CodeRetriever(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.cache_dir , self.logger)
                usages = retriever.get_symbol_references(func_name, Retriever.Parser)
                # filter the usage including the Function entry
                example = filter_examples(usages, self.project_lang, self.usage_token_limit)
               
                # comment the example
                example = "// ".join(example.splitlines())
                example = "// " + example
                # TODO 
                if example != "":
                    error_msg += f"\n // the usage of {func_name} is as follows: \n" + example

        return self.fuzz_fix_prompt.format(harness_code=harness_code, error_msg=error_msg, project_lang=self.project_lang)

    def respond(self, state: dict):
        fix_counter = state.get("fix_counter", 0)
        last_message = state["messages"][-1].content
        if fix_counter == 0 or self.clear_msg_flag:
            # clear previous messages, need to build the fix prompt based on the provided template 
            state["messages"].clear()
            if last_message.startswith(CompileResults.CodeError):
                fix_prompt = self.build_compile_prompt(state["harness_code"], state["build_msg"])
            else:
                fix_prompt = self.build_fuzz_prompt(state["harness_code"], state["fuzz_msg"])
        else:
            # keep the previous messages, just add the error message
            if last_message.startswith(CompileResults.CodeError):
                fix_prompt = "Complie Error Messages:\n" + state["build_msg"]
            else:
                fix_prompt = "Fuzz Error Messages:\n" + state["fuzz_msg"]

        return {"messages": ("user", fix_prompt)}

class SemaCheckNode:
    def __init__(self, oss_fuzz_dir: str, project_name: str, new_project_name: str, function_signature: str, 
                 project_lang, logger: logging.Logger):
        self.oss_fuzz_dir = oss_fuzz_dir
        self.project_name = project_name
        self.new_project_name = new_project_name
        self.func_name = extract_name(function_signature)
        self.logger = logger
        self.checker = SemaCheck(oss_fuzz_dir, project_name, new_project_name, self.func_name, project_lang)

    def check(self, state: dict):
        # run semantic check
        flag = self.checker.check(state["harness_code"], state["fuzzer_path"], state["fuzzer_name"])
        if flag:
            self.logger.info("Semantic check passed")
            return{"messages": ("user", END + "Semantic check passed")}
        else:
            self.logger.info("Semantic check failed")
            msg = "The harness code is grammly correct, but it could not pass the semantic check. The reason is the harness code does not correctly fuzz the function." \
            " Maybe the harness code didn't correctly feed the fuzze data to correct position (like file or buffer)." 
            return{"messages": ("user", "Semantic check failed"), "fuzz_msg": msg}

class ISSTAFuzzer(AgentFuzzer):
    SemanticCheckNode = "SemanticCheckNode"
    def __init__(self, model_name: str, oss_fuzz_dir: str, project_name: str, function_signature: str, usage_token_limit: int,
                 run_time: int, max_fix: int, max_tool_call: int, clear_msg_flag:bool, save_dir: str, cache_dir: str):
        super().__init__(model_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit, run_time, 
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
        retriever = CodeRetriever(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.cache_dir , self.logger)
        
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
            # random_index = 16
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
        elif len(retrieved_signature) > 1:
            self.logger.warning(f"Multiple signature found for {function_name}, use the provided signature from xml")
        else:
            function_signature = retrieved_signature[0]["source_code"]
            if function_signature.replace(" ", "").replace("\n", "").replace("\t", "") != self.function_signature.replace(" ", "").replace("\n", "").replace("\t", "")+";":
                self.logger.error(f"Retrieved signature is different from the provided one: {function_signature} vs {self.function_signature}")

        prompt_template = prompt_template.format(header_files=header, function_usage=function_usage, function_document=function_document,
                                             function_signature=self.function_signature, function_name=function_name)
        prompt_template += "{\n"
        save_code_to_file(prompt_template, os.path.join(self.save_dir, "prompt.txt"))

        return prompt_template


    def fuzzer_router_mapping(self, state):
        last_message = state["messages"][-1]

        # print(messages)
        if last_message.content.startswith(FuzzResult.NoError):
            return self.SemanticCheckNode
        elif last_message.content.startswith(END):
            return END
        else:
            return self.FixBuilderNode
        
    def semantic_check_router_mapping(self, state):
        last_message = state["messages"][-1]

        if last_message.content.startswith(END):
            return END
        else:
            return self.FixBuilderNode
    def build_graph(self):

        llm = ChatOpenAI(model=self.model_name, temperature=0.7)

        code_retriever = CodeRetriever(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.cache_dir, self.logger)
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
        fix_builder = FixerPromptBuilder(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.cache_dir, self.usage_token_limit, self.logger,
                                        compile_fix_prompt, fuzz_fix_prompt, self.project_lang, clear_msg_flag=self.clear_msg_flag)

        code_fixer = CodeFixer(fixer_llm, self.max_fix, self.max_tool_call,  self.save_dir, self.cache_dir,
                                 code_callback=code_formater.extract_code, logger=self.logger)

        fuzzer = FuzzerWraper(self.oss_fuzz_dir, self.new_project_name, self.project_lang, 
                             self.run_time,  self.save_dir,  self.logger)
        
        compiler = CompilerWraper(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang, self.harness_pairs, self.save_dir, self.logger)
        checker = SemaCheckNode(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.function_signature, self.project_lang, self.logger)

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
        builder.add_node(self.SemanticCheckNode, checker.check)

        # add edges
        builder.add_edge(START, self.HarnessGeneratorNode)
        builder.add_edge(self.HarnessGeneratorNode, self.CompilerNode)
        builder.add_edge(self.FixerToolNode, self.CodeFixerNode)
        builder.add_edge(self.FixBuilderNode, self.CodeFixerNode)

        # add conditional edges
        builder.add_conditional_edges(self.CompilerNode, self.compile_router_mapping,  [self.FixBuilderNode, self.FuzzerNode, END])
        builder.add_conditional_edges(self.CodeFixerNode, self.code_fixer_mapping,  [self.CompilerNode, self.FixerToolNode, END])
        builder.add_conditional_edges(self.FuzzerNode, self.fuzzer_router_mapping, [self.FixBuilderNode,  self.SemanticCheckNode, END])
        builder.add_conditional_edges(self.SemanticCheckNode, self.semantic_check_router_mapping, [self.FixBuilderNode, END])

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


def process_project(llm_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call, save_dir, cache_dir):

    try:
        agent_fuzzer = ISSTAFuzzer(llm_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit=usage_token_limit, run_time=run_time, max_fix=max_fix,
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

        res_file = os.path.join(save_dir, f"issta{i}", f"success_name.pkl")
        if not os.path.exists(res_file):
            continue
            
        with open(res_file, "rb") as f:
            success_sig = pickle.load(f)
            all_success_sig.extend(success_sig)

    return all_success_sig


def run_parallel(iteration=1):
    # build graph
    oss_fuzz_dir = "/home/yk/code/oss-fuzz/"
    # absolute path
    save_dir = os.path.join(PROJECT_PATH, "outputs", "issta_apr7")
    cur_save_dir = os.path.join(save_dir, f"issta{iteration}")
    cache_dir = "/home/yk/code/LLM-reasoning-agents/cache/"
    llm_name = "gpt-4-0613"
    run_time=0.5
    max_fix=5
    max_tool_call=15
    usage_token_limit = 1000
    function_dict = {}

    if iteration > 1:
        all_success_func = get_all_successful_func(save_dir, iteration)
    else:
        all_success_func = []

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
            # project_harness = data.get("target_path")
            # if project_name not in ["igraph", "liblouis", "libmodbus", "libyang", "lua", "pjsip", "quickjs", "seliux", 
                                    # "coturn", "gdk-pixbuf", "kamilio", "igraph", "liblouis", "libmodbus", "libyang", "lua", "pjsip", "quickjs", "seliux"]:
            # continue

            if lang_name not in ["c++", "c"]:
                continue
        
            function_list = []
            for function in data.get("functions"):
                function_signature = function["signature"]
                function_name = extract_name(function_signature)
                
                if function_name not in ["get_src_uri", "parse_from_uri", "parse_identityinfo_header", 
                                        ]:
                    continue
                
                # # not success
                # if function_name in all_success_func:
                #     continue
                
                # # not in the removed list
                # if function_name in REMOVED_FUNC:
                #     continue

                total += 1
                function_list.append(function_signature)

            # 
            if len(function_list) != 0:
                function_dict[project_name] = function_list
                max_num_function = max(max_num_function, len(function_list))

    print("total projects:", total)
    # os.cpu_count()//2
    with Pool(processes=os.cpu_count()//3) as pool:

        for i in range(max_num_function):
            for key in function_dict.keys():
                if i >= len(function_dict[key]):
                    continue
                function_signature = function_dict[key][i]
                project_name = key
                print(f"{i+1}th of functions in {key}: {len(function_dict[key])}")
                # llm_name, oss_fuzz_dir, project_name, function_signature, run_time, max_fix, max_tool_call, save_dir, cache_dir
                # pool.apply(process_project, args=(llm_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call,  cur_save_dir, cache_dir))
                pool.apply_async(process_project, args=(llm_name, oss_fuzz_dir, project_name, function_signature, usage_token_limit, run_time, max_fix, max_tool_call,  cur_save_dir, cache_dir))

                
        pool.close()
        pool.join()

    run_agent_res(cur_save_dir)


def run_single():
      # build graph
    OSS_FUZZ_DIR = "/home/yk/code/oss-fuzz/"
    PROJECT_NAME = "w3m"

    # absolute path
    CACHE_DIR = "/home/yk/code/LLM-reasoning-agents/cache/"
    # llm_name = "gpt-4o-mini"
    llm_name = "gpt-4-0613"
    # llm_name = "gpt-4o"
    # function_signature =
    # func_list = [
    #     "int parse_content_disposition(struct sip_msg *)",
    #     "int parse_diversion_header(struct sip_msg *)",
    #     "int parse_headers(struct sip_msg *const msg, const hdr_flags_t flags, const int next)",
    #     "int parse_identityinfo_header(struct sip_msg *)",
    #     "int parse_to_header(const struct sip_msg *)",
    #     "sip_uri_t * parse_to_uri(const sip_msg_t *)"
    # ]
    # func_list = [
        # "int parse_record_route_headers(sip_msg_t *)",
        # "int parse_route_headers(sip_msg_t *)",
        # "int get_src_uri(sip_msg_t *, int, str *)",
        # "int parse_pai_header(const struct sip_msg *)",
    # ]
    func_list = ["Str wc_Str_conv_with_detect(Str, wc_ces *, wc_ces, wc_ces)"]
    # func_list = ["int32_t llama_vocab_n_tokens(const struct llama_vocab * vocab);"]
    # func_list = ["GdkPixbufAnimation* gdk_pixbuf_animation_new_from_file(const char         *filename, GError  **error)"]

    for function_signature in func_list:
        for i in range(1,2):
            SAVE_DIR = f"/home/yk/code/LLM-reasoning-agents/outputs/llamacpp/issta{i}/"
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
    run_parallel(3)
    # run_single()