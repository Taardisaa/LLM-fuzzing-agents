from constants import LanguageType, LSPFunction
from tools.code_tools.parsers.c_parser import CParser
from tools.code_tools.parsers.cpp_parser import CPPParser
from tools.code_tools.parsers.base_parser import BaseParser
from pathlib import Path
from typing import Optional

class CCPPParser(BaseParser):
    def __init__(self, file_path: Optional[Path], source_code: Optional[str] = None, project_lang: LanguageType = LanguageType.CPP):
        super().__init__(file_path, source_code, project_lang=project_lang)
        self.file_path = file_path
        self.source_code = source_code
        self.project_lang = project_lang
        self.cparser = CParser(file_path, source_code)
        self.cppparser = CPPParser(file_path, source_code)
        self.parser_order: list[BaseParser] = [self.cparser, self.cppparser]
        if self.project_lang == LanguageType.CPP:
            self.parser_order = [self.cppparser, self.cparser]

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: LSPFunction) ->  tuple[str, str, int]:
        for parser in self.parser_order:
            key, src_code, start_line = parser.get_symbol_source(symbol_name, line, lsp_function)
            if src_code:
                return key, src_code, start_line
        return "", "", 0
    
    def get_file_functions(self) -> list[str]:
        for parser in self.parser_order:
            src_code = parser.get_file_functions()
            if src_code:
                return src_code
        return []


# Example usage
if __name__ == "__main__":
    file_path = "/home/yk/code/LLM-reasoning-agents/tools/code_tools/parsers/demo.c"  # Replace with your C/C++ file path
    line = 4 # Replace with the line number of the function's start position
    # column = 38  # Replace with the column number of the function's start position

    # IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream);
    # TODO CPP is better for the above function, we should try to use CPP if C is not working
    extractor = CCPPParser(Path(file_path), project_lang=LanguageType.C)
    extracted_code = extractor.get_symbol_source("ISC_LEXCOMMENT_DNSMASTERFILE", line, LSPFunction.Declaration)
    print("Function source code:")
    print(extracted_code)