from tree_sitter import Language, Parser, Node, Query
import tree_sitter_c  # For C language
import tree_sitter_cpp  # For C++ language
import tree_sitter_java  # For Java language
from constants import LanguageType, FuzzEntryFunctionMapping, LSPFunction
from pathlib import Path
from typing import Optional

parser_language_mapping = {
    LanguageType.C: tree_sitter_c.language(),
    LanguageType.CPP: tree_sitter_cpp.language(),
    LanguageType.JAVA: tree_sitter_java.language(),
}

class BaseParser:
    def __init__(self, file_path: Optional[Path], source_code: Optional[str] = None,
                 decl_query_dict: dict[str, str] = {}, def_query_dict: dict[str, str] = {}, 
                 func_declaration_query_dict: dict[str, str] = {},
                 project_lang: LanguageType = LanguageType.CPP):
        
        self.decl_query_dict = decl_query_dict
        self.def_query_dict = def_query_dict
        self.func_declaration_query_dict = func_declaration_query_dict
        self.file_path = file_path
        self.project_lang = project_lang
        self.parser_language = self.set_language(project_lang)
        self.parser = Parser(self.parser_language)

        if source_code:
            assert isinstance(source_code, str)
            self.source_code = bytes(source_code, "utf-8")
        elif file_path:
            self.source_code = file_path.read_bytes()
        else:
            raise ValueError("Either source code or file path must be provided.")
        
        # for fuzzing
        self.call_func_name, self.func_def_name = self.name_mapping()
        self.tree = self.parser.parse(self.source_code)

    def set_language(self, language: LanguageType) -> Language:
        assert language in parser_language_mapping.keys(), f"Language {language} not supported."
        return Language(parser_language_mapping[language])

    def name_mapping(self):
        call_name_dict = {
            LanguageType.C: "call_expression",
            LanguageType.CPP: "call_expression",
            LanguageType.JAVA: "method_call",
        }
        func_def_name_dict = {
            LanguageType.C: "function_definition",
            LanguageType.CPP: "function_definition",
            LanguageType.JAVA: "method_declaration",
        }

        return call_name_dict[self.project_lang], func_def_name_dict[self.project_lang]

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: LSPFunction) -> tuple[str, str, int]:
        """
        Retrieve the full source code of a symbol based on its start position.
        :param symbol_name: The name of the function to find.
        :param line: The line number of the function's start position (0-based).
        :param column: The column number of the function's start position (0-based).
        :return: The full source code of the function.
        """
        def exec_query(query: Query, query_node: Node, line: int, node_name:str="node_name") -> tuple[str, int]:
            
            # Execute the query
            captures = query.captures(query_node)
            if not captures:
                return "", 0
            
            for source_node in captures[node_name]:
            
                # TODO will this find the definition that calls the function?
                if not source_node.text:
                    continue
                if source_node.start_point.row <= line and line <= source_node.end_point.row:  
                    return source_node.text.decode("utf-8", errors="ignore") , source_node.start_point.row
            return "", 0
     
        # print("language: ", self.project_lang)
        # print("parser_language: ", self.parser_language)
        # type s
        if lsp_function == LSPFunction.Declaration:
            query_dict = self.decl_query_dict
        elif lsp_function == LSPFunction.Definition:
            query_dict = self.def_query_dict
        else:
            print("Unsupported LSP function.")
            return "", "", 0
            
        for key, query_str in query_dict.items():
            # Execute the query
            query_str = query_str.format(symbol_name)
            query = self.parser_language.query(query_str)
            src_code, start_line = exec_query(query, self.tree.root_node, line)
            if src_code:
                # Decode the source code to a string
                return key, src_code, start_line

        return "", "", 0
    

    def get_file_functions(self) -> list[str]:
        
        ret_list: list[str] = []
        for _, query in self.func_declaration_query_dict.items():
            # Execute the query
            query = self.parser_language.query(query)
            captures = query.captures(self.tree.root_node)
            if not captures:
                continue

            for source_node in captures["node_name"]:
                # if we can't decode the text, it is meaningless to search
                if not source_node.text:
                    continue

                # Decode the source code to a string
                src_code = source_node.text.decode("utf-8", errors="ignore")
                # function declaration must include (
                if src_code:
                    ret_list.append(src_code)
        
        return ret_list

    # def get_related_source(self, symbol_name: str, line: int) -> tuple[str, str]:
    #     """
    #     Retrieve the source code of the function that calls the given symbol.
    #     :param symbol_name: The name of the function to find.
    #     :param line: The line number of the function's start position (0-based).
    #     :return: The source code of the function that calls the given symbol.
    #     """
    #     def exec_query(query: Query, query_node: Node, symbol_name: str, line: int, identifier_name: str="type") -> str:
    
    #         # Execute the query
    #         captures = query.captures(query_node)
    #         if not captures:
    #             return ""
            
    #         for source_node in captures["node_name"]:
            
    #             # TODO will this find the definition that calls the function?
    #             if not source_node.text:
    #                 continue
    #             captures = query.captures(source_node)
    #             if identifier_name not in captures:
    #                 continue

    #             for id_node in captures[identifier_name]:
    #                 if not id_node.text:
    #                     continue

    #                 name = id_node.text.decode("utf-8", errors="ignore") 
    #                 name = name.strip()
    #                 if name.startswith("*"):
    #                    name = name[1:].strip()  # Remove leading '*'
    #                 if name.startswith("struct"):
    #                     name = name[6:].strip()

    #                 if name == symbol_name and  source_node.start_point.row <= line and line <= source_node.end_point.row:  
    #                     return source_node.text.decode("utf-8", errors="ignore") 
    #         return ""

    #     for key, query in self.func_declaration_query_dict.items():
    #         # Execute the query
    #         query = self.parser_language.query(query)
    #         for identifier_name in ["type", "value"]:
    #             src_code = exec_query(query, self.tree.root_node, symbol_name, line, identifier_name)
    #             if src_code:
    #                 # Decode the source code to a string
    #                 return key, src_code

    #     return "", ""
    
    def get_ref_source(self, symbol_name: str, line: int) -> str:

        # find the callee node
        callee_node = None
        query = self.parser_language.query(f"({self.call_func_name}) @func_call")

        # Execute the query
        captures = query.captures( self.tree.root_node)

        if not captures:
            return ""

        # Print the nodes
        for node in captures["func_call"]:
            # if we can't decode the text, it is meaningless to search
            if not node.text:
                continue

            source_code = node.text.decode("utf-8", errors="ignore")
            # function call may span multiple lines so we need to check the range
            if (node.start_point.row <= line or line <= node.end_point.row) and symbol_name in source_code:
                callee_node = node
                break
        
        if not callee_node:
            return ""

        # all the way to the top of the first function definition
        while callee_node.parent:
            callee_node = callee_node.parent
            if callee_node.type == self.func_def_name:
                break
        if callee_node.text:
            return callee_node.text.decode("utf-8", errors="ignore")

        return ""

        # find the upper node of the callee node, which is reference node
        
    def get_call_node(self, function_name: str, entry_node: Optional[Node] = None) -> Optional[Node]:
        if not entry_node:
            print("Entry function not found.")
            return None

        # Define a query to find "function_call" nodes
        function_call_query = self.parser_language.query(f"({self.call_func_name}) @func_call")

        # Execute the query
        captures = function_call_query.captures(entry_node)
        if not captures:
            return None
            
        # Print the nodes
        for node in captures["func_call"]:
            try:
                # TODO C/C++ function name is the first child of the call expression
                if node.children[0].text and function_name == node.children[0].text.decode("utf-8", errors="ignore"):
                    return node
            except Exception as e:
                print("Error in parsing the function call: ", e)
        return None

    def get_fuzz_function_node(self, function_name: str) -> Optional[Node]:
        """
        Get the position of a function in the source code.
        :param function_name: The name of the function to find.
        :return: The position of the function in the source code.
        """
        # TODO this only works for call fuzz function directly in the entry function
        # Fist find the Fuzz entry point
        entry_function = FuzzEntryFunctionMapping[self.project_lang]
        entry_node = self.get_definition_node(entry_function)
        return self.get_call_node(function_name, entry_node)
      
    def is_fuzz_function_called(self, function_name: str) -> bool:
        if self.get_fuzz_function_node(function_name):
            return True
        return False
    
    def exist_function_definition(self, function_name: str) -> bool:
        if self.get_definition_node(function_name):
            return True
        return False

    def get_definition_node(self, function_name: str) -> Optional[Node]:
        # TODO this only test on C/C++ language
        
        # Define a query to find "function_definition" nodes
        function_definition_query = self.parser_language.query(f"({self.func_def_name}) @func_def")

        # Execute the query
        captures = function_definition_query.captures(self.tree.root_node)

        # Check the nodes
        for node in captures["func_def"]:

            try:
                for child in node.children:
                    # TODO this only test on C/C++ language
                    if child.type != "function_declarator":
                        continue
                    
                    # the function name is under function_declarator
                    if child.children[0].text and function_name == child.children[0].text.decode("utf-8", errors="ignore"):
                        return node
            except Exception as e:
                print("Error in parsing the function definition: ", e)
        
        return None
       
    def get_child_node(self, node: Node, field_name: str) -> Optional[Node]:
        """
        Get the child node of a node by field name.
        :param node: The parent node.
        :param field_name: The field name of the child node.
        :return: The child node.
        """
        for child in node.children:
            if child.type == field_name:
                return child
        return None