from tree_sitter import Language, Parser
import tree_sitter_c  # For C language
import tree_sitter_cpp  # For C++ language
import tree_sitter_java  # For Java language
from constants import LanguageType, FuzzEntryFunctionMapping, LSPFunction
from tools.code_tools.parsers.base_parser import BaseParser

class CParser(BaseParser):
    def __init__(self, file_path: str, source_code: str = None, project_lang: LanguageType = LanguageType.CPP):
        super().__init__(file_path, source_code, project_lang)

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: str) -> str:
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
                source_code = node.text.decode("utf-8", errors="ignore")
                # fcuntion declaration and definition may span multiple lines so we need to check the range
                if node.start_point.row <= line and  line <= node.end_point.row and symbol_name in source_code:
                    return source_code
                
                # # some rare case, 
                # # IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream);
                # nex_node = node.next_named_sibling  
                # if (query != declaration_query) or (not nex_node):
                #     continue

                # source_code = nex_node.text.decode("utf-8", errors="ignore")
                # if nex_node.start_point.row <= line and  line <= nex_node.end_point.row and symbol_name in source_code:
                #     return source_code


# Example usage
if __name__ == "__main__":
    file_path = "tools/code_tools/parsers/demo.c"  # Replace with your C/C++ file path
    line = 1  # Replace with the line number of the function's start position
    column = 0  # Replace with the column number of the function's start position

    extractor = CParser(file_path, project_lang=LanguageType.C)
    extracted_code = extractor.get_symbol_source("bpf_object__open_mem", line, LSPFunction.Declaration)
    print("Function source code:")
    print(extracted_code)