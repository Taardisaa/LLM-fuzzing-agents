import json
import os
import argparse
from tools.code_tools.lsp_clients.c_lsp_client import CLSPCLient
from tools.code_tools.lsp_clients.multi_lsp_client import MultilspyClient
import asyncio
from tools.code_tools.parsers.c_cpp_parser import CCPPParser
from tools.code_tools.parsers.java_parser import JavaParser
from constants import LanguageType, LSPFunction, LSPResults
from typing import Any
from pathlib import Path

class LSPCodeRetriever():
    def __init__(self, workdir: str,  project_lang: LanguageType, symbol_name: str, lsp_function: LSPFunction):
   
        self.project_root = workdir
        self.symbol_name = symbol_name
        self.lsp_function = lsp_function
        self.project_lang = project_lang
        self.lang_parser = self.get_language_parser()
        self.lsp_client = self.get_lsp_client()

    def get_language_parser(self):
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            return CCPPParser
        elif self.project_lang == LanguageType.JAVA:
            return JavaParser
        else:
            raise Exception(f"Language {self.project_lang} not supported.")
    
    def get_lsp_client(self):
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            return CLSPCLient(self.project_root, self.project_lang)
        else:
            return MultilspyClient(self.project_root, self.project_lang) 
        
    def fectch_code(self, file_path: str, lineno: int, lsp_function: LSPFunction) -> list[dict[str, Any]]:

        query_key = ""
        start_line = 0
        parser = self.lang_parser(Path(file_path), source_code=None, project_lang=self.project_lang)
        if lsp_function == LSPFunction.References:
            # get the full source code of the symbol
            source_code = parser.get_ref_source(self.symbol_name, lineno) # type: ignore
        else:
            query_key, source_code, start_line = parser.get_symbol_source(self.symbol_name, lineno, lsp_function)

        if source_code:
            return [{"source_code": source_code, "file_path": file_path, "line": lineno, "type": query_key, "start_line": start_line}]

        return []

    def fectch_code_from_response(self, response: list[dict[str, Any]], lsp_function: LSPFunction) -> list[dict[str, Any]]:
        """
        Convert the response from clangd to a source code.
        Args:
            response (dict): The response from clangd.
        Returns:
            list[dict]: The list of source code and corresponding file.
        """
     
        # there may be multiple locations for cross-references
        #  [{'range': {'end': {'character': 7, 'line': 122}, 'start': {'character': 2, 'line': 122}}, 'uri': 'file:///src/cjson/cJ                                                                                                           SON.h'}]}
        if not response:
            return []
        
        ret_list: list[dict[str, Any]] = []
        for loc in response:  
            file_path = loc.get("uri", "").replace("file://", "")
            range_start = loc['range']['start']

            source_dict = self.fectch_code(file_path, range_start['line'], lsp_function)
            ret_list += source_dict 

        return ret_list


    async def request_function(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        """
        Args:
            file_path (str): The C++ source file including the symbol.
            lineno (int): The line number where the symbol is located.
            charpos (int): The character position within the line where the symbol is located.
        Returns:
            list[dict]: The list of source code and corresponding file.
        Raises:
            Exception: If there is an error during the request to the LSP server.
        """
        
        response = []
        # Find declaration
        # for C/C++, the lsp is very strange, if the symbol already is the declaration, request_declaration will return the definition
        # if the symbol is already a definition, definition will return the declaration
        # this will cause the parser to fail to find the declaration or the definition, so we also need to parser the symbol location to make sure
        # we get the correct declaration or definition, this may return multiple definitions for rare cases like "typdef struct"

        if self.lsp_function == LSPFunction.Declaration:
            response = await self.lsp_client.request_declaration(file_path, lineno=lineno, charpos=charpos)
            resp_list =  self.fectch_code_from_response(response, self.lsp_function)
            resp_list += self.fectch_code(file_path, lineno, self.lsp_function)
            return resp_list
    
        elif self.lsp_function == LSPFunction.Definition:
            response = await self.lsp_client.request_definition(file_path, lineno=lineno, charpos=charpos)
            
            resp_list =  self.fectch_code_from_response(response, self.lsp_function)
            resp_list += self.fectch_code(file_path, lineno, self.lsp_function)
            return resp_list
        
        elif self.lsp_function == LSPFunction.References:
            response = await self.lsp_client.request_references(file_path, lineno=lineno, charpos=charpos)
            return self.fectch_code_from_response(response, self.lsp_function)
        else:
            raise Exception(f"Unsupported LSP function: {self.lsp_function}")

    async def find_all_symbols(self) -> tuple[str, list[tuple[str, int, int]]]:
        
        # Find declaration
        response = await self.lsp_client.request_workspace_symbols(self.symbol_name)

        if not response:
            print("Empty response. Dot close the server, it will stuck")
            return f"{LSPResults.Error.value}, Empty Response.", []

        return LSPResults.Success.value, response


    async def get_symbol_info(self) -> tuple[str, list[dict[str, Any]]]:
        """
        Finds information about a given symbol in the project.
        This method searches for the specified symbol within the project directory
        using the `grep` command. It then attempts to locate the symbol's definition,
        declaration, or references using the Language Server Protocol (LSP) for C/C++.
        Returns:
            list[dict]: A list of dictionaries containing information about the symbol.
                If the symbol is not found, an empty string is returned.
        """
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            msg, all_symbols = await self.find_all_symbols()
            
            if len(all_symbols) == 0:
                return msg, []
        else:
            raise Exception(f"Language {self.project_lang} not supported.")

        # all_symbols should be only one
        # if len(all_symbols) > 1:
            # return f"{LSPResults.Error}: More than one symbol found. {all_symbols}", []
        
        print("num of total file: ", len(all_symbols))

        final_resp: list[dict[str, Any]] = []
        all_source_code: list[str] = []

        for file_path, lineno, char_pos in all_symbols:
            print("file_path:{}, lineno:{}, char_pos:{}".format(file_path, lineno, char_pos))
            # Define server arguments
            try:
                response = await self.request_function(file_path,  int(lineno), int(char_pos))

                for res_json in response:
                    if res_json["source_code"] not in all_source_code:
                        final_resp.append(res_json)
                        all_source_code.append(res_json["source_code"])
            except Exception as e:
                print(f"Error: {e}")
                return f"{LSPResults.Error.value}: {e}", []
        
        return LSPResults.Success.value, final_resp

    
async def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--workdir', type=str, help='The work place that can run bear compile.')
    parser.add_argument('--lsp-function', type=str, choices=[e.value for e in LSPFunction], help='The LSP function name')
    parser.add_argument('--symbol-name', type=str, help='The function name or struct name.')
    parser.add_argument('--lang', type=str, choices=[e.value for e in LanguageType], help='The project language.')
    args = parser.parse_args()

    # the default workdir is the current directory, since we didn't send the compile_comamnd.json to the clangd server
    lsp = LSPCodeRetriever(args.workdir, LanguageType(args.lang), args.symbol_name, LSPFunction(args.lsp_function))
    msg, res = await lsp.get_symbol_info()

    file_name = f"{lsp.symbol_name}_{lsp.lsp_function.value}_lsp.json"
    with open(os.path.join("/out", file_name), "w") as f:
        f.write(json.dumps({"message": msg, "response": res}, indent=4))


if __name__ == "__main__":
    asyncio.run(main())