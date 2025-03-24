import json
import os
from urllib.parse import unquote, urlparse
import argparse
import subprocess as sp
from tools.code_tools.lsp_clients.c_lsp_client import CLSPCLient
from tools.code_tools.lsp_clients.multi_lsp_client import MultilspyClient
import asyncio
from tools.code_tools.parsers.c_parser import CParser
from tools.code_tools.parsers.java_parser import JavaParser
from constants import LanguageType, LSPFunction, LSPResults


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
            return CParser
        elif self.project_lang == LanguageType.JAVA:
            return JavaParser
        else:
            raise Exception(f"Language {self.project_lang} not supported.")
    
    def get_lsp_client(self):
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            return CLSPCLient(self.project_root, self.project_lang.lower())
        else:
            return MultilspyClient(self.project_root, self.project_lang.lower()) 
        
    def fetch_code(self, response: dict) -> list[dict]:
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
        
        ret_list = []
        for loc in response:  
            file_path = loc.get("uri", "").replace("file://", "")
            range_start = loc['range']['start']

            parser = self.lang_parser(file_path, source_code=None, project_lang=self.project_lang)
            if self.lsp_function == LSPFunction.References:
                # get the full source code of the symbol
                source_code = parser.get_ref_source(self.symbol_name, range_start['line'])
            else:
                source_code = parser.get_symbol_source(self.symbol_name, range_start['line'], self.lsp_function)

            if source_code:
                ret_list.append({"source_code": source_code, "file_path": file_path, "line": range_start['line']})

        return ret_list


    async def request_function(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
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
        
        if self.lsp_function == LSPFunction.Header:
            # Find declaration
            response = await self.lsp_client.request_declaration(file_path, lineno=lineno, charpos=charpos )
            if not response:
                return []

            ret_list = []
            for loc in response:
                file_path = loc.get("uri", "").replace("file://", "")
                # head file doesn't need the source code, it's hard to parse the source code cause the sambol is very different 
                ret_list.append({"source_code": "", "file_path": file_path, "line": loc['range']['start']['line']})
            return ret_list
        # Find declaration
        elif self.lsp_function == LSPFunction.Declaration:
            response = await self.lsp_client.request_declaration(file_path, lineno=lineno, charpos=charpos)
        elif self.lsp_function == LSPFunction.Definition:
            response = await self.lsp_client.request_definition(file_path, lineno=lineno, charpos=charpos)
        elif self.lsp_function == LSPFunction.References:
            response = await self.lsp_client.request_references(file_path, lineno=lineno, charpos=charpos)

        return self.fetch_code(response)

    async def find_all_symbols(self) -> list[tuple[str, int, int]]:
        
        # Find declaration
        response = await self.lsp_client.request_workspace_symbols(self.symbol_name)

        if not response:
            print("Empty response. Dot close the server, it will stuck")
            return f"{LSPResults.Error}, Empty Response.", []

        return LSPResults.Success, response


    async def get_symbol_info(self) -> list[dict]:
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

        # all_symbols should be only one
        # if len(all_symbols) > 1:
            # return f"{LSPResults.Error}: More than one symbol found. {all_symbols}", []
        
        print("num of total file: ", len(all_symbols))

        final_resp = []
        all_source_code = []

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
                return f"{LSPResults.Error}: {e}", []
        
        return LSPResults.Success, final_resp

    
async def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--workdir', type=str, help='The work place that can run bear compile.')
    parser.add_argument('--lsp-function', type=str, choices=[LSPFunction.Definition, LSPFunction.Declaration, LSPFunction.References, LSPFunction.Header], help='The LSP function name')
    parser.add_argument('--symbol-name', type=str, help='The function name or struct name.')
    parser.add_argument('--lang', type=str, choices=[LanguageType.C, LanguageType.CPP,  LanguageType.JAVA], help='The project language.')
    args = parser.parse_args()

    # the default workdir is the current directory, since we didn't send the compile_comamnd.json to the clangd server
    lsp = LSPCodeRetriever(args.workdir, args.lang, args.symbol_name, args.lsp_function)
    msg, res = await lsp.get_symbol_info()

    file_name = f"{lsp.symbol_name}_{lsp.lsp_function}_lsp.json"
    with open(os.path.join("/out", file_name), "w") as f:
        f.write(json.dumps({"message": msg, "response": res}, indent=4))


if __name__ == "__main__":
    asyncio.run(main())