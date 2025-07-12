#!/usr/bin/env python3
"""
使用 tree-sitter 从项目头文件中提取所有函数声明并去重
"""

import os
import glob
from pathlib import Path
from typing import Set, List, Dict, Optional
from tree_sitter import Language, Parser, Node, Query
import tree_sitter_c  # For C language
import tree_sitter_cpp  # For C++ language
from constants import LanguageType

class FunctionDeclaration:
    """函数声明信息"""
    def __init__(self, name: str, signature: str, file_path: str, line_number: int, 
                 function_type: str = "function", namespace: str = ""):
        self.name = name
        self.signature = signature
        self.file_path = file_path
        self.line_number = line_number
        self.function_type = function_type
        self.namespace = namespace
        self.full_name = f"{namespace}::{name}" if namespace else name
    
    def __str__(self):
        return f"{self.full_name}: {self.signature} ({self.file_path}:{self.line_number})"
    
    def __repr__(self):
        return f"FunctionDeclaration({self.name}, {self.file_path}:{self.line_number})"
    
    def __eq__(self, other):
        if not isinstance(other, FunctionDeclaration):
            return False
        return self.full_name == other.full_name and self.signature == other.signature
    
    def __hash__(self):
        return hash((self.full_name, self.signature))

class HeaderFunctionExtractor:
    """头文件函数声明提取器"""
    
    def __init__(self, project_root: str = "/src/ada-url"):
        self.project_root = Path(project_root)
        self.parser_language_mapping = {
            LanguageType.C: tree_sitter_c.language(),
            LanguageType.CPP: tree_sitter_cpp.language(),
        }
        
        # Tree-sitter 查询语句用于提取函数声明
        self.function_queries = {
            "function_declaration": """
                (function_declarator
                    (identifier) @function_name
                    (parameter_list) @params
                ) @declaration
            """,
            
            "function_definition": """
                (function_definition
                    (function_declarator
                        (identifier) @function_name
                        (parameter_list) @params
                    )
                ) @definition
            """,
            
            "method_declaration": """
                (field_declaration
                    (function_declarator
                        (field_identifier) @function_name
                        (parameter_list) @params
                    )
                ) @declaration
            """,
            
            "template_function": """
                (template_declaration
                    (function_definition
                        (function_declarator
                            (identifier) @function_name
                            (parameter_list) @params
                        )
                    )
                ) @declaration
            """,
            
            "template_function_declaration": """
                (template_declaration
                    (declaration
                        (function_declarator
                            (identifier) @function_name
                            (parameter_list) @params
                        )
                    )
                ) @declaration
            """,
            
            "constructor_declaration": """
                (field_declaration
                    (function_declarator
                        (field_identifier) @function_name
                        (parameter_list) @params
                    )
                ) @declaration
            """,
            
            "destructor_declaration": """
                (field_declaration
                    (function_declarator
                        (field_identifier) @function_name
                        (parameter_list) @params
                    )
                ) @declaration
            """
        }
        
        # 简化的查询语句
        self.simple_queries = {
            "all_functions": """
                [
                    (function_declarator
                        (identifier) @function_name
                        (parameter_list) @params
                    )
                    (function_declarator
                        (field_identifier) @function_name
                        (parameter_list) @params
                    )
                ] @declaration
            """,
            
            "namespaces": """
                (namespace_definition
                    (namespace_identifier) @namespace_name
                ) @namespace
            """,
            
            "classes": """
                (class_specifier
                    (type_identifier) @class_name
                ) @class
            """
        }
    
    def get_language(self, file_path: Path) -> Optional[LanguageType]:
        """根据文件扩展名确定语言类型"""
        suffix = file_path.suffix.lower()
        if suffix in ['.h', '.c']:
            return LanguageType.C
        elif suffix in ['.hpp', '.hh', '.hxx', '.cpp', '.cc', '.cxx']:
            return LanguageType.CPP
        return None
    
    def find_header_files(self) -> List[Path]:
        """查找所有头文件"""
        header_files = []
        
        # 查找 include 目录下的头文件
        include_dir = self.project_root / "include"
        if include_dir.exists():
            for pattern in ["**/*.h", "**/*.hpp", "**/*.hh", "**/*.hxx"]:
                header_files.extend(include_dir.glob(pattern))
        
        # 查找 src 目录下的头文件
        src_dir = self.project_root / "src"
        if src_dir.exists():
            for pattern in ["**/*.h", "**/*.hpp", "**/*.hh", "**/*.hxx"]:
                header_files.extend(src_dir.glob(pattern))
        
        return sorted(list(set(header_files)))
    
    def extract_functions_from_file(self, file_path: Path) -> List[FunctionDeclaration]:
        """从单个文件中提取函数声明"""
        language_type = self.get_language(file_path)
        if not language_type:
            return []
        
        try:
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # 设置解析器
            language = Language(self.parser_language_mapping[language_type])
            parser = Parser(language)
            
            # 解析代码
            tree = parser.parse(bytes(source_code, 'utf-8'))
            
            functions = []
            
            # 使用简化的查询提取函数
            query_text = self.simple_queries["all_functions"]
            query = language.query(query_text)
            
            captures = query.captures(tree.root_node)
            
            # 检查是否有 captures
            if not captures:
                return functions
                
            # 从 captures 中提取函数名
            for capture_name, nodes in captures.items():
                if capture_name == "function_name":
                    for node in nodes:
                        function_name = node.text.decode('utf-8')
                        
                        # 获取参数列表
                        params_node = None
                        for sibling in node.parent.children:
                            if sibling.type == "parameter_list":
                                params_node = sibling
                                break
                        
                        if params_node:
                            params_text = params_node.text.decode('utf-8')
                            signature = f"{function_name}{params_text}"
                        else:
                            signature = function_name
                        
                        # 获取行号
                        line_number = node.start_point[0] + 1
                        
                        # 创建函数声明对象
                        func_decl = FunctionDeclaration(
                            name=function_name,
                            signature=signature,
                            file_path=str(file_path),
                            line_number=line_number,
                            function_type="function"
                        )
                        
                        functions.append(func_decl)
            
            return functions
            
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
            return []
    
    def extract_all_functions(self) -> Dict[str, List[FunctionDeclaration]]:
        """提取所有头文件中的函数声明"""
        header_files = self.find_header_files()
        print(f"Found {len(header_files)} header files")
        
        all_functions = {}
        
        for file_path in header_files:
            print(f"Processing: {file_path}")
            functions = self.extract_functions_from_file(file_path)
            if functions:
                all_functions[str(file_path)] = functions
        
        return all_functions
    
    def deduplicate_functions(self, all_functions: Dict[str, List[FunctionDeclaration]]) -> Dict[str, FunctionDeclaration]:
        """对函数进行去重"""
        unique_functions = {}
        
        for file_path, functions in all_functions.items():
            for func in functions:
                key = func.full_name
                if key not in unique_functions:
                    unique_functions[key] = func
                else:
                    # 如果已存在，保留更完整的签名
                    existing = unique_functions[key]
                    if len(func.signature) > len(existing.signature):
                        unique_functions[key] = func
        
        return unique_functions
    
    def generate_report(self, unique_functions: Dict[str, FunctionDeclaration]) -> str:
        """生成函数列表报告"""
        report_lines = []
        report_lines.append("# 函数声明提取报告")
        report_lines.append(f"## 总计找到 {len(unique_functions)} 个唯一函数")
        report_lines.append("")
        
        # 按文件分组
        functions_by_file = {}
        for func in unique_functions.values():
            file_path = func.file_path
            if file_path not in functions_by_file:
                functions_by_file[file_path] = []
            functions_by_file[file_path].append(func)
        
        # 按文件输出
        for file_path in sorted(functions_by_file.keys()):
            rel_path = os.path.relpath(file_path, self.project_root)
            report_lines.append(f"### {rel_path}")
            report_lines.append("")
            
            functions = sorted(functions_by_file[file_path], key=lambda f: f.line_number)
            for func in functions:
                report_lines.append(f"- **{func.name}** (line {func.line_number})")
                report_lines.append(f"  - 签名: `{func.signature}`")
                report_lines.append("")
        
        # 按字母顺序列出所有函数名
        report_lines.append("## 所有函数名列表（按字母顺序）")
        report_lines.append("")
        for func_name in sorted(unique_functions.keys()):
            report_lines.append(f"- {func_name}")
        
        return "\n".join(report_lines)


def main():
    """主函数"""
    print("开始提取函数声明...")
    
    # 创建提取器
    extractor = HeaderFunctionExtractor()
    
    # 提取所有函数
    all_functions = extractor.extract_all_functions()
    
    # 去重
    unique_functions = extractor.deduplicate_functions(all_functions)
    
    # 生成报告
    report = extractor.generate_report(unique_functions)
    
    # 保存报告
    report_file = Path("/src/ada-url/function_declarations_report.md")
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"提取完成！找到 {len(unique_functions)} 个唯一函数")
    print(f"报告已保存到: {report_file}")
    
    # 打印统计信息
    print("\n统计信息:")
    print(f"- 总文件数: {len(all_functions)}")
    print(f"- 总函数数: {sum(len(funcs) for funcs in all_functions.values())}")
    print(f"- 唯一函数数: {len(unique_functions)}")


if __name__ == "__main__":
    main()
