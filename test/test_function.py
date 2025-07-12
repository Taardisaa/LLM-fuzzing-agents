from tree_sitter import Language, Parser
from pathlib import Path
import tree_sitter_c
import tree_sitter_cpp

# Build language lib if not already built


lang = Language(tree_sitter_c.language())
parser = Parser(lang)

code_path = Path("/home/yk/code/LLM-reasoning-agents/tools/code_tools/parsers/demo.c")
tree = parser.parse(code_path.read_bytes())


# Query to extract parameters of functions
query1 = lang.query("""
(
  declaration
    declarator: (function_declarator
      declarator: (identifier) @func_name
      parameters: (parameter_list
        (parameter_declaration
          type: (_) @type
          declarator: (_) @param))))@node_name
""")

# Query to extract parameters of functions
query2 = lang.query("""
(
  declaration
    declarator: (pointer_declarator
    declarator: (function_declarator
      declarator: (identifier) @func_name
      parameters: (parameter_list
        (parameter_declaration
          type: (_) @type
          declarator: (_) @param)))))@node_name
""")

func_def = """(function_definition
                    declarator: (function_declarator
                    declarator: (identifier) @identifier_name
                    (#eq? @identifier_name "{}")
                    )) @node_name"""

func_def = func_def.format("dns_decompress_setpermitted")

query4 = lang.query(func_def)
query3 = lang.query("""(enum_specifier
                        name: (type_identifier) @enum.name
                        body: (enumerator_list
                                (enumerator
                                name: (identifier) @enum.member
                                (#eq? @enum.member "DNS_DECOMPRESS_ALWAYS")
                                )
                            ) @enum.body
                    ) @node_name""")

for query in [query4]:
    captures = query.captures(tree.root_node)

    for node in captures["node_name"]:
        
        sec_captures = query.captures(node)

        if not sec_captures:
            continue
        print(f"Node: {node.text.decode('utf-8')}")
        # for sub_node in sec_captures["param"]:
            # print(sub_node.text.decode('utf-8'))