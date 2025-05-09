from utils.docker_utils import DockerUtils
from constants import ToolDescMode, LanguageType, LSPFunction
import json
import os
import logging
from constants import LSPResults, Retriever, DockerResults, PROJECT_PATH
from pathlib import Path
from typing import Callable, Any
import functools

header_desc_mapping = {
        ToolDescMode.Simple: """
        get_symbol_header(symbol_name)-> str:

        this function can find the header file that declare the symbol name.
        :param symbol_name: The symbol name like class name, function name, struct name etc.
        :return: Full path to the header file if found, otherwise None.
        """,
        ToolDescMode.Detailed:  """
        get_symbol_header(symbol_name)-> str:
        
        this function can find the header file that declare the symbol name. Please keep the namespace of the symbol name if they have.
        Do not include space in the symbol name.
        :param symbol_name: The symbol name like class name, function name, struct name etc.
        :return: Full path to the header file if found, otherwise None.

        Example:
            get_symbol_header("cJSON") -> "../cJSON.h"
            get_symbol_header("ada::parser::parse_url<ada::url>") -> "ada.h"

        """
    }


def catch_exception(func: Callable[..., list[dict[str, str]]]) -> Callable[..., list[dict[str, str]]]:
    @functools.wraps(func)
    def wrapper(self: Any, *args: Any, **kwargs: Any)->list[dict[str, str]]: 
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            self.logger.error(f"Error in {func.__name__}: {str(e)}") # type: ignore
            return []
    return wrapper # type: ignore

class CodeRetriever():
    # TODO: how to deal with the same symbol name in different files, we may not know the file path
    '''
    This class is used to retrieve the code information for a project through LSP and language parser.
    It run a python file lsp_code_retriever inside the docker container to get the code information. Therefore, those python files should be copied to the docker container first.
    The python file implementes the LSP client to interact with different LSP servers (clangd for c/c++, ) to get the following information:
    1. Header file path for a symbol name.
    2. Symbol declaration for a symbol name.
    3. Symbol definition for a symbol name.
    4. Symbol cross reference for a symbol name.
    '''

    def __init__(self, oss_fuzz_dir: Path, project_name: str, new_project_name: str, 
                 project_lang: LanguageType, cache_dir: Path, logger: logging.Logger):

        self.oss_fuzz_dir = oss_fuzz_dir
        self.project_name = project_name
        self.new_project_name = new_project_name
        self.project_lang = project_lang
        self.cache_dir = cache_dir
        self.logger = logger
        self.docker_tool = DockerUtils(self.oss_fuzz_dir, self.project_name, self.new_project_name, self.project_lang)


    def view_code(self, file_path: str, line_start: int, line_end: int) -> str:
        """
        Reads a specific portion of code from the file path.
        Args:
            file_path (str): The path to the file to read from.
            line_start (int): The starting line number (0-indexed).
            line_end (int): The ending line number (0-indexed).
        Returns:
            str: The extracted code as a string.
        """
        # Read the file from the docker container
        read_cmd = f"sed -n '{line_start + 1},{line_end + 1}p' {file_path}"

        result = self.docker_tool.run_cmd(read_cmd)
        # sed 
        if "sed: " in result:
            self.logger.warning(result)
            return ""
        return result
    
    # def get_all_functions(header_file: str) -> list:
    #     """
    #     """
        
    @catch_exception
    def call_container_code_retriever(self, symbol_name: str, lsp_function: LSPFunction, retriver: Retriever) -> list[dict[str, str]]:

        compile_out_path = self.oss_fuzz_dir / "build" / "out" / self.new_project_name
        compile_out_path.mkdir(parents=True, exist_ok=True)
        compile_json_path = self.cache_dir / self.project_name / "compile_commands.json"
        workdir = self.docker_tool.run_cmd(["pwd"], timeout=None, volumes=None).strip()
        volumes:dict[str, dict[str, str]] = {str(compile_out_path): {"bind": "/out", "mode": "rw"}, 
                    os.path.join(PROJECT_PATH, "tools"): {"bind": os.path.join(workdir, "tools"), "mode": "ro"}}

        if retriver == Retriever.LSP:
            pyfile = "lsp_code_retriever"
            if self.project_lang in [LanguageType.C, LanguageType.CPP]:
                # the host file must exist for mapping
                if not compile_json_path.exists():
                    self.logger.error(f"Error: {compile_json_path} does not exist")
                    return []
                volumes[str(compile_json_path)] = {"bind": os.path.join(workdir, "compile_commands.json"), "mode": "rw"}

        elif retriver == Retriever.Parser:
            pyfile = "parser_code_retriever"
        else:
            self.logger.error(f"Error: {retriver} is not supported")
            return []
        
        cmd_list:list[str] = ["python", "-m", f"tools.code_tools.{pyfile}",  "--workdir", workdir,  "--lsp-function", lsp_function.value,
                     "--symbol-name", symbol_name, "--lang", self.project_lang.value]
        
        res_str = self.docker_tool.run_cmd(cmd_list, timeout=60, volumes=volumes)
        self.logger.info(f"Calling {retriver}_code_retriever to get {lsp_function} for {symbol_name}")
       
        # docker run error 
        if res_str.startswith(DockerResults.Error.value):
            self.logger.error(f"Error in when calling {retriver}_code_retriever: {res_str}")
            return []

        # check if the response file is generated
        file_name = f"{symbol_name}_{lsp_function.value}_{retriver.value}.json"
        save_path = compile_out_path / file_name
        if not save_path.exists():
            self.logger.error(f"Error: {retriver}_code_retriever does not generate the response file: {save_path}")
            return []
        
        # read code retriver response
        with open(save_path, "r") as f:
            res_json = json.load(f)

        msg, lsp_resp = res_json["message"], res_json["response"]

        if msg.startswith(LSPResults.Error.value):
            self.logger.error(f"Error in when calling {retriver}_code_retriever: {msg}")
            return []
        
        if not lsp_resp:
            self.logger.info(f"{retriver}_code_retriever return [], {lsp_function} for {symbol_name}")
            return []
        
        return lsp_resp


    @catch_exception
    def get_symbol_info(self, symbol_name: str, lsp_function: LSPFunction, retriever: Retriever = Retriever.Mixed) -> list[dict[str, str]]:
        """
        Retrieves the declaration information of a given symbol using the Language Server Protocol (LSP).
        Args:
            symbol_name (str): The name of the symbol for which to retrieve the declaration.
        Returns:
             list[dict]: [{"source_code":"", "file_path":"", "line":""}]
        """

        # Remove the "struct" or "class" prefix from the symbol name
        if symbol_name.startswith("struct") or symbol_name.startswith("class"):
            symbol_name = symbol_name.split(" ")[1]

        if retriever == Retriever.Mixed:
            lsp_resp = self.get_symbol_info_retriever(symbol_name, lsp_function, Retriever.LSP)
            # two cases: 1. no lsp response, 2. lsp response is the wrong header file (lsp may be wrong)
            if not lsp_resp:
                lsp_resp = self.get_symbol_info_retriever(symbol_name, lsp_function, Retriever.Parser)
            elif lsp_function == LSPFunction.Header:
                call_parser = False
                for resp in lsp_resp:
                    header_file = resp.get("file_path", "")
                    file_type = header_file.split('.')[-1]

                    # the lsp may return the wrong file type, need to call parser to get the correct file type
                    if file_type not in [ 'h', 'hpp', 'hh', 'hxx']:
                        call_parser = True
                        break
                if call_parser: 
                    lsp_resp = self.get_symbol_info_retriever(symbol_name, lsp_function, Retriever.Parser)
            
        else:
            lsp_resp = self.get_symbol_info_retriever(symbol_name, lsp_function, retriever)

        return lsp_resp
    

    @catch_exception
    def get_symbol_info_retriever(self, symbol_name: str, lsp_function: LSPFunction, retriever: Retriever = Retriever.LSP) -> list[dict[str, str]]:
        """
        Retrieves the declaration information of a given symbol using the Language Server Protocol (LSP).
        Args:
            symbol_name (str): The name of the symbol for which to retrieve the declaration.
        Returns:
             list[dict]: [{"source_code":"", "file_path":"", "line":""}]
        """

        save_path = self.cache_dir / self.project_name / f"{symbol_name}_{lsp_function.value}_{retriever.value}.json"
        # get the lsp response from the cache if it exists
        if save_path.exists():
            self.logger.info(f"Getting {lsp_function} for {symbol_name} from cache")
            with open(save_path, "r") as f:
                return json.load(f)
        
        # call the container code retriever
        lsp_resp = self.call_container_code_retriever(symbol_name, lsp_function, retriever)
    
        if self.cache_dir.exists():
            save_path.parent.mkdir(parents=True, exist_ok=True)
            # TODO: same symbol name
            with open(save_path, "w") as f:
                json.dump(lsp_resp, f)

        return lsp_resp


    def get_symbol_header(self, symbol_name: str, retriever: Retriever = Retriever.Mixed) -> str:
        """
        Find the header file path containing the declaration of a specified symbol name.
        Args:
            symbol_name (str): The name of the symbol to search for like function name, struct name, class name .. .
        Returns:
            str: If the declaration is found, returns the absolute path to the header file.
                 If no declaration is found, returns None.
        Example:
            >>> get_symbol_header("cJSON")
            "/src/cJSON.h"
            >>> get_symbol_header("ada::parser::parse_url<ada::url>")
            "/src/ada-url/ada/url.h"
        """
        name_list = symbol_name.split("::")
        for i in range(len(name_list)):
            new_symbol_name = "::".join(name_list[i:])
            declaration = self.get_symbol_info(new_symbol_name, LSPFunction.Header, retriever)

            if len(declaration) > 1:
                self.logger.warning(f"Multiple declaration found for {new_symbol_name}, please check the symbol name")

                header_set: set[str] = set()
                for decl in declaration:
                    header_set.add(decl["file_path"])
                
                all_headers = "\n".join(header_set)
                return all_headers
            elif len(declaration) == 1:
                absolute_path = declaration[0]["file_path"]
                return absolute_path
            
        self.logger.warning(f"No such symbol: {symbol_name} found!")
        return LSPResults.NoResult.value # No declaration found

    def get_symbol_declaration(self, symbol_name: str, retriever: Retriever = Retriever.Mixed) -> list[dict[str, str]]:
        """
        Get the declaration of a symbol from the project.
        Args:
            symbol_name (str): The name of the symbol to find the declaration for
        Returns:
            str: The declaration of the symbol, or None if not found
                For multiple declarations, returns a combined result
        Example:
            >>> code_retriever.get_symbol_declaration("MyClass")
            [{'source_code': 'MyClass {...}',
              'file_path': '/src/xx',
              'line': 10}]
        """
        
        declaration = self.get_symbol_info(symbol_name, LSPFunction.Declaration, retriever)
        # handle multiple declaration
        return declaration

    def get_symbol_definition(self, symbol_name: str, retriever: Retriever = Retriever.Mixed) -> list[dict[str, str]]:
        """
        Retrieves the definition(s) for a specified symbol using LSP.
        Args:
            symbol_name (str): The name of the symbol to look up
            retriever (str, optional): The retriever strategy to use. Defaults to Retriever.Mixed.
        Returns:
            Union[List[Location], None]: List of locations where the symbol is defined, or None if not found.
            Each location contains file path and position information.
        See Also:
            get_symbol_info(): The underlying method used to get symbol information
            
        Example:
            >>> code_retriever.get_symbol_definition("cJSON_Parse")
            [{'source_code': 'cJSON *cJSON_Parse(const char *value) {...}',
              'file_path': '/src/cJSON.c',
              'line': 120}]
        """
        # limit the code length to 50 lines
        res = self.get_symbol_info(symbol_name, LSPFunction.Definition, retriever)
        if len(res) > 1:
            self.logger.warning(f"Multiple definition found for {symbol_name}, please check the symbol name")
        elif len(res) == 0:
            self.logger.warning(f"No definition found for {symbol_name}, please check the symbol name")
            return []
        
        source_code = res[0]["source_code"]
        # only keep the first 50 lines
        source_code_lines = source_code.split("\n")
        source_code = "\n".join(source_code_lines[:50])
        return [{
            "source_code": source_code,
            "file_path": res[0]["file_path"],
            "line": res[0]["line"]
        }]

    def get_symbol_references(self, symbol_name: str, retriever: Retriever = Retriever.Parser) -> list[dict[str, str]]:
        """
        Get references to a symbol across all workspace files.
        Args:
            symbol_name (str): The name of the symbol to find references for
        Returns:
            list: A list of functions that used the symbol name in the workspace
        Example:
            >>> references = get_symbol_references("cJSON_Parse")
            >>> references
            [{'source_code': 'function1 {...}',
              'file_path': '/src/xx',
              'line': 10},
             {'source_code': 'function2 {...}',
              'file_path': '/src/yy',
              'line': 20}]
        """

        return self.get_symbol_info(symbol_name, LSPFunction.References, retriever)
