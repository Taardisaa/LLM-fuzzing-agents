from constants import LanguageType, LSPFunction
from tools.code_tools.parsers.base_parser import BaseParser
from pathlib import Path
from typing import Optional

# TODO no consider template yet

def_query_dict = {
    "fucntion": """(function_definition
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                     (#eq? @identifier_name "{}"))) @node_name""",
    "pointer_function": """(function_definition
                    declarator: (pointer_declarator
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                    (#eq? @identifier_name "{}")
                    ))) @node_name""",

    "method": """(function_definition
                    declarator: (function_declarator
                        declarator: (qualified_identifier
                        (identifier) @identifier_name
                         (#eq? @identifier_name "{}"))))@node_name""",
    "classes": """
        (class_specifier
            name: (type_identifier) @identifier_name
             (#eq? @identifier_name "{}"))@node_name""",
    "macro_func": """(preproc_function_def
                    name: (identifier) @identifier_name
                     (#eq? @identifier_name "{}")
                    ) @node_name""",

    "macro_definition": """(preproc_def
                    name: (identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "type_definition": """(type_definition
                    type: (_) @struct_name
                    declarator: (_) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "struct": """(struct_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "union": """(union_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "enum": """(enum_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "enum_dedefinition": """(enum_specifier
                        name: (type_identifier) @enum.name
                        body: (enumerator_list
                                (enumerator
                                name: (identifier) @identifier_name
                                (#eq? @identifier_name "{}")
                                )
                            ) @enum.body
                    ) @node_name"""
        }

decl_query_dict = {
    "declaration": """(declaration
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                     (#eq? @identifier_name "{}"))) @node_name""",
    "pointer_declaration": """(declaration
                    declarator: (pointer_declarator
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                     (#eq? @identifier_name "{}")
                    ))) @node_name""",
    "method": """(field_declaration
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                     (#eq? @identifier_name "{}"))) @node_name""",
   "macro_func": """(preproc_function_def
                    name: (identifier) @identifier_name
                     (#eq? @identifier_name "{}")
                    ) @node_name""",

    "macro_definition": """(preproc_def
                    name: (identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "type_definition": """(type_definition
                    type: (_) @struct_name
                    declarator: (_) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "struct": """(struct_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "union": """(union_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "enum": """(enum_specifier
                    name: (type_identifier) @identifier_name
                    (#eq? @identifier_name "{}")) @node_name""",
    "enum_dedefinition": """(enum_specifier
                        name: (type_identifier) @enum.name
                        body: (enumerator_list
                                (enumerator
                                name: (identifier) @identifier_name
                                (#eq? @identifier_name "{}")
                                )
                            ) @enum.body
                    ) @node_name"""
}


related_query_dict = {
            "normal_ret":   """
            (
            declaration
                declarator: (function_declarator
                declarator: (identifier) @func_name
                parameters: (parameter_list
                    (parameter_declaration
                    type: (_) @type
                    declarator: (_) @value))))@node_name
            """,
            "pointer_ret": """
            (
            declaration
                declarator: (pointer_declarator
                declarator: (function_declarator
                declarator: (identifier) @func_name
                parameters: (parameter_list
                    (parameter_declaration
                    type: (_) @type
                    declarator: (_) @value)))))@node_name
            """,

}

class CPPParser(BaseParser):
    def __init__(self, file_path: Optional[Path], source_code: Optional[str] = None):
        super().__init__(file_path, source_code,decl_query_dict, def_query_dict, related_query_dict, LanguageType.CPP)

# Example usage
if __name__ == "__main__":
    file_path = Path("/src/bind9/tools/code_tools/parsers/demo.cpp")  # Replace with your C/C++ file path
    line = 40 # Replace with the line number of the function's start position
    column = 0  # Replace with the column number of the function's start position

    # IGRAPH_EXPORT igraph_error_t igraph_read_graph_pajek(igraph_t *graph, FILE *instream);
    # TODO CPP is better for the above function, we should try to use CPP if C is not working
    extractor = CPPParser(file_path)
    extracted_code = extractor.get_symbol_source("bark", line, LSPFunction.Definition)
    print("Function source code:")
    print(extracted_code)