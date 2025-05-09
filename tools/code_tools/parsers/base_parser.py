from tree_sitter import Language, Parser, Node
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
                  project_lang: LanguageType = LanguageType.CPP):
        
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

    def get_symbol_source(self, symbol_name: str, line: int, lsp_function: LSPFunction) -> str:
        raise NotImplementedError


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