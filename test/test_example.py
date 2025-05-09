from tree_sitter import Language, Parser
import tree_sitter_c

# Load compiled C parser

parser = Parser(Language(tree_sitter_c.language()))


# Memory ops to track
MEMORY_FUNCS = {'memcpy', 'strcpy', 'memmove', 'memset'}

# Start with known sources: e1, e2
SOURCE_VARS = {'e1', 'e2'}

def node_text(code, node):
    return code[node.start_byte:node.end_byte].decode('utf-8')

def analyze_code(code: str):
    tree = parser.parse(code)
    root_node = tree.root_node

    # Taint map: var -> set of sources
    taint = {v: {v} for v in SOURCE_VARS}

    def walk(node, parent_taint=None):
        if node.type == 'assignment_expression':
            left = node.child_by_field_name('left')
            right = node.child_by_field_name('right')
            left_name = node_text(code, left)
            right_expr = node_text(code, right)

            # Find which sources are in the right side
            influencing = set()
            for tvar in taint:
                if tvar in right_expr:
                    influencing |= taint[tvar]
            if influencing:
                if left_name not in taint:
                    taint[left_name] = set()
                taint[left_name] |= influencing

        elif node.type == 'call_expression':
            func_name_node = node.child_by_field_name('function')
            args_node = node.child_by_field_name('arguments')
            if func_name_node and args_node:
                func_name = node_text(code, func_name_node).strip()
                args = [node_text(code, arg).strip() for arg in args_node.children if arg.type != ',']
                print(f"\nFound function call: {func_name}({', '.join(args)})")
                for i, arg in enumerate(args):
                    for tvar in taint:
                        if tvar in arg:
                            for src in taint[tvar]:
                                print(f"  → arg{i+1} ({arg}) is derived from {src}")
                # Track memory operation side effects
                if func_name in MEMORY_FUNCS:
                    if len(args) >= 2:
                        dest, src = args[0], args[1]
                        for tvar in taint:
                            if tvar in src:
                                if dest not in taint:
                                    taint[dest] = set()
                                taint[dest] |= taint[tvar]

        for child in node.children:
            walk(child)

    walk(root_node)

if __name__ == "__main__":
    code_snippet = """
    void E(e1, e2) {
        struct S { int x; } s;
        s.x = e1;
        char buf1[10], buf2[10];
        memcpy(buf1, &e2, 10);
        A(s.x, buf1[0]);
    }
    """
    analyze_code(bytes(code_snippet, "utf-8"))
