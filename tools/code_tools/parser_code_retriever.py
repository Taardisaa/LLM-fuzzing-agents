import json
import os
from urllib.parse import unquote, urlparse
import argparse
import subprocess as sp
import random
from tools.code_tools.parsers.c_parser import CParser
from tools.code_tools.parsers.java_parser import JavaParser
from constants import LanguageType, LSPFunction, LSPResults


class ParserCodeRetriever():
    def __init__(self, workdir: str,  project_lang: LanguageType, symbol_name: str, lsp_function: LSPFunction, max_try: int = 100):
   
        self.project_root = workdir
        self.symbol_name = symbol_name
        self.lsp_function = lsp_function
        self.project_lang = project_lang
        self.max_try = max_try
        self.lang_parser = self.get_language_parser()
    
    def get_language_parser(self):
        if self.project_lang in [LanguageType.C, LanguageType.CPP]:
            return CParser
        elif self.project_lang == LanguageType.JAVA:
            return JavaParser
        else:
            raise Exception(f"Language {self.project_lang} not supported.")
    
    def fetch_code(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
        """
        Find the definition of a symbol in a C or C++ file using Clangd LSP.
        Args:
            file_path (str): The C++ source file including the symbol.
            lineno (int): The line number where the symbol is located.
            charpos (int): The character position within the line where the symbol is located.
        Returns:
            list[dict]: The list of source code and corresponding file.
        Raises:
            Exception: If there is an error during the request to the LSP server.
        """
        # cpp for C++
        ret_list = []
        parser = self.lang_parser(file_path, source_code=None, project_lang=self.project_lang)
        if self.lsp_function == LSPFunction.References:
            # get the full source code of the symbol
            source_code = parser.get_ref_source(self.symbol_name, lineno)
        elif self.lsp_function == LSPFunction.Header:
            source_code = parser.get_symbol_source(self.symbol_name, lineno, LSPFunction.Declaration)
        else:
            source_code = parser.get_symbol_source(self.symbol_name, lineno, self.lsp_function)

        if source_code:
            ret_list.append({"source_code": source_code, "file_path": file_path, "line": lineno})

        return ret_list

    def get_symbol_info(self) -> list[dict]:
        """
        Finds information about a given symbol in the project.
        This method searches for the specified symbol within the project directory
        using the `grep` command. It then parse all file contains the symbol and extract information using tree-sitter.
        Returns:
            list[dict]: A list of dictionaries containing information about the symbol.
                If the symbol is not found, an empty string is returned.
        """
        
        # Execute `find` command to recursively list files and directories
        if self.lsp_function == LSPFunction.References:
            cmd = f"grep --binary-files=without-match -rn {self.project_root} -e  '{self.symbol_name}('"
        else:
            cmd = f"grep --binary-files=without-match -rnw {self.project_root} -e  {self.symbol_name}"

        results = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT,  text=True)
        output = results.stdout.strip()

        if not output:
            return []

        # the location may be in the comments or in the string literals
        # find the file path, line number and character position
        all_lines = output.splitlines()

        # filter some files by file type
        filtered_lines = []
        for line in all_lines:
            
            parts = line.split(':', 2)
            # check if the line is valid
            if len(parts) < 3:
                continue

            file_path, lineno, content = parts
            # filter the other files (.md, .txt, etc)
            file_type = file_path.split('.')[-1]

            if self.lsp_function in [LSPFunction.Header, LSPFunction.Declaration]:
                filter_header = [ 'h', 'hpp', 'hh', 'hxx', "java"]
            else:
                filter_header = [ 'c', 'cc', 'cpp', 'cxx', 'c++',  "java"]

            if file_type not in filter_header:
                continue
            
            # find character position
            char_pos = content.find(self.symbol_name)
            # the line number is 1-based, we need to convert it to 0-based
            filtered_lines.append((file_path, int(lineno)-1, char_pos))

        print("num of total file: ", len(filtered_lines))
        # shuffle the list to get random files
        random.shuffle(filtered_lines)

        final_resp = []
        all_source_code = []

        for file_path, lineno, char_pos in filtered_lines[:self.max_try]:
            print("file_path:{}, lineno:{}, char_pos:{}".format(file_path, lineno, char_pos))
            # Define server arguments
            try:
                response = self.fetch_code(file_path,  lineno, int(char_pos))
                for res_json in response:
                    if res_json["source_code"] not in all_source_code:
                        final_resp.append(res_json)
                        all_source_code.append(res_json["source_code"])
            except Exception as e:
                return f"{LSPResults.Error}: {e}", []
        
        return LSPResults.Success, final_resp
    
def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--workdir', type=str, default="/src/", help='The search directory.')
    parser.add_argument('--lsp-function', type=str, choices=[LSPFunction.Definition, LSPFunction.Declaration, LSPFunction.References, LSPFunction.Header], help='The LSP function name')
    parser.add_argument('--symbol-name', type=str, help='The function name or struct name.')
    parser.add_argument('--lang', type=str, choices=[LanguageType.C, LanguageType.CPP,  LanguageType.JAVA], help='The project language.')
    args = parser.parse_args()

    try:
        lsp = ParserCodeRetriever(args.workdir, args.lang, args.symbol_name, args.lsp_function)
        msg, res = lsp.get_symbol_info()
    except Exception as e:
        msg = f"{LSPResults.Error}: {e}"
        res = []

    file_name = f"{lsp.symbol_name}_{lsp.lsp_function}_parser.json"
    with open(os.path.join("/out", file_name), "w") as f:
        f.write(json.dumps({"message": msg, "response": res}, indent=4))

if __name__ == "__main__":
    main()