from constants import LanguageType, LSPFunction
from tools.code_tools.parsers.base_parser import BaseParser
from pathlib import Path
from typing import Optional

class CParser(BaseParser):
    def __init__(self, file_path: Optional[Path], source_code: Optional[str] = None, project_lang: LanguageType = LanguageType.CPP):
        super().__init__(file_path, source_code, project_lang)

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: LSPFunction) -> str:
        """
        Retrieve the full source code of a symbol based on its start position.
        :param symbol_name: The name of the function to find.
        :param line: The line number of the function's start position (0-based).
        :param column: The column number of the function's start position (0-based).
        :return: The full source code of the function.
        """
        # Define a query to find "definition" and "declaration" nodes
        #  TODO: Test on other languages. Only tested on C/C++.
        definition_query = self.parser_language.query("""
        (function_definition) @func_decl
        """)
        declaration_query = self.parser_language.query("""
        (declaration) @func_decl
        """)
        type_definition_query = self.parser_language.query("""
        (type_definition) @func_decl
        """)
        struct_specifier_query = self.parser_language.query("""
        (struct_specifier) @func_decl
        """)
        enum_specifier_query = self.parser_language.query("""
        (enum_specifier) @func_decl
        """)

        print("language: ", self.project_lang)
        print("parser_language: ", self.parser_language)
        # type s
        if lsp_function == LSPFunction.Declaration:
            query_list = [declaration_query, type_definition_query, struct_specifier_query, enum_specifier_query]
        elif lsp_function == LSPFunction.Definition:
            query_list = [type_definition_query, struct_specifier_query, definition_query]
        else:
            print("Unsupported LSP function.")
            return ""
            
        for query in query_list:

            # Execute the query
            captures = query.captures(self.tree.root_node)
            
            if not captures:
                continue
            
            # Print the nodes
            for node in captures["func_decl"]:
            
                # TODO will this find the definition that calls the function?
                if not node.text:
                    continue
                source_code = node.text.decode("utf-8", errors="ignore")
                # fcuntion declaration and definition may span multiple lines so we need to check the range
                if node.start_point.row <= line and  line <= node.end_point.row and symbol_name in source_code:
                   
                    if query != definition_query:
                        return source_code

                    # check if the saymbol name is called in the function
                    declarator_node = self.get_child_node(node, "function_declarator")

                    if not declarator_node:
                        continue
                    
                    # find the identifier node since it is the method name
                    identifier_node = self.get_child_node(declarator_node, "identifier")
                    if not identifier_node or not identifier_node.text:
                        continue
                    # same as the symbol name
                    if identifier_node.text.decode("utf-8", errors="ignore") == symbol_name:
                        return source_code

        return ""

# Example usage
if __name__ == "__main__":
    file_path = Path("/home/yk/code/LLM-reasoning-agents/tools/code_tools/parsers/demo.c")  # Replace with your C/C++ file path
    line = 16 # Replace with the line number of the function's start position
    column = 0  # Replace with the column number of the function's start position

    # IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream);
    # TODO CPP is better for the above function, we should try to use CPP if C is not working
    extractor = CParser(file_path, project_lang=LanguageType.C)
    extracted_code = extractor.get_symbol_source("LLVMFuzzerTestOneInput", line, LSPFunction.Definition)
    print("Function source code:")
    print(extracted_code)