from tree_sitter import Parser
from constants import LanguageType, LSPFunction
from tools.code_tools.parsers.c_parser import CParser
from pathlib import Path
from typing import Optional

class CCPPParser(CParser):
    def __init__(self, file_path: Optional[Path], source_code: Optional[str] = None, project_lang: LanguageType = LanguageType.CPP):
        super().__init__(file_path, source_code, project_lang)

    # 
    def switch_language(self):
        if self.project_lang == LanguageType.C:
            self.project_lang = LanguageType.CPP
        elif self.project_lang == LanguageType.CPP:
            self.project_lang = LanguageType.C
        
        self.parser_language = super().set_language(self.project_lang)
        self.parser = Parser(self.parser_language)
        self.tree = self.parser.parse(self.source_code)
        self.call_func_name, self.func_def_name = self.name_mapping()

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: LSPFunction) -> str:
        
        src_code = super().get_symbol_source(symbol_name, line, lsp_function)
        if src_code:
            return src_code
        
        print("switching language")
        # change to C if the current language is C++, the parser is sensitive to the language
        self.switch_language()
        src_code = super().get_symbol_source(symbol_name, line, lsp_function)
        return src_code


# Example usage
if __name__ == "__main__":
    file_path = "/home/yk/code/LLM-reasoning-agents/tools/code_tools/parsers/demo.c"  # Replace with your C/C++ file path
    line = 0 # Replace with the line number of the function's start position
    column = 38  # Replace with the column number of the function's start position

    # IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream);
    # TODO CPP is better for the above function, we should try to use CPP if C is not working
    extractor = CCPPParser(Path(file_path), project_lang=LanguageType.CPP)
    extracted_code = extractor.get_symbol_source("igraph_read_graph_pajek", line, LSPFunction.Definition)
    print("Function source code:")
    print(extracted_code)