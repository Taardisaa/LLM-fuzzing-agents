#!/usr/bin/env python3
"""
Simplified C++ Function Extractor using libclang

Extracts function information from C++ source files using compile_commands.json.
Outputs simplified JSON with: function name, namespace::class, file location, line number.
"""

import json
import os
import sys
from typing import Dict, List, Set, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
import clang.cindex
from clang.cindex import CursorKind, Index, TranslationUnit

from clang.cindex import Index, CursorKind, Config
# Config.set_library_file('/usr/local/lib/python3.11/site-packages/clang/native/libclang.so')  # adjust for your system
Config.set_library_file('/usr/lib/llvm-18/lib/libclang.so') 
@dataclass
class FunctionInfo:
    """Simplified function information"""
    name: str
    namespace_class: str
    file_path: str
    line_number: int

class LibclangFunctionExtractor:
    """Simplified C++ function extractor using libclang and compile_commands.json"""
    
    def __init__(self, project_root: str):
        """
        Initialize the function extractor
        
        Args:
            project_root: Root directory of the project to filter functions
        """
        self.project_root = Path(project_root).resolve()
        self.extracted_functions: Dict[str, FunctionInfo] = {}
        self.index = Index.create()
    
    def _get_namespace_class(self, cursor) -> str:
        """Get namespace::class qualification"""
        parts = []
        parent = cursor.semantic_parent
        
        while parent and parent.kind != CursorKind.TRANSLATION_UNIT:
            if parent.kind == CursorKind.NAMESPACE:
                parts.append(parent.spelling)
            elif parent.kind in [CursorKind.CLASS_DECL, CursorKind.STRUCT_DECL, 
                               CursorKind.CLASS_TEMPLATE]:
                parts.append(parent.spelling)
            parent = parent.semantic_parent
        
        return "::".join(reversed(parts))
    
    def _is_project_file(self, file_path: str) -> bool:
        """Check if file is within project directory"""
        try:
            file_path = Path(file_path).resolve()
            return str(file_path).startswith(str(self.project_root))
        except:
            return False
    
    def _extract_function_info(self, cursor) -> Optional[FunctionInfo]:
        """Extract simplified function information"""
        if cursor.kind not in [CursorKind.FUNCTION_DECL, CursorKind.CXX_METHOD, 
                              CursorKind.CONSTRUCTOR, CursorKind.DESTRUCTOR]:
            return None
        
        if not cursor.spelling:
            return None
        
        location = cursor.location
        if not location.file:
            return None
        
        file_path = str(location.file)
        
        # Only include functions from project files
        if not self._is_project_file(file_path):
            return None
        
        namespace_class = self._get_namespace_class(cursor)
        
        return FunctionInfo(
            name=cursor.spelling,
            namespace_class=namespace_class,
            file_path=file_path,
            line_number=location.line
        )
    
    def _traverse_ast(self, cursor):
        """Recursively traverse AST and extract functions"""
        func_info = self._extract_function_info(cursor)
        if func_info:
            # Use namespace_class::name as unique key for deduplication
            # This will keep only one instance of each function signature
            key = f"{func_info.namespace_class}::{func_info.name}" if func_info.namespace_class else func_info.name
            
            # Only add if not already present (keeps the first occurrence)
            if key not in self.extracted_functions:
                self.extracted_functions[key] = func_info
        
        for child in cursor.get_children():
            self._traverse_ast(child)
    
    def analyze_file(self, directory: str, src_file: str, args: List[str]):
        """Analyze a single file from compile_commands.json"""
        file_path = os.path.join(directory, src_file) if not os.path.isabs(src_file) else src_file
        
        if not os.path.exists(file_path):
            return
        
        # try:
        # Helper function to resolve include paths
        def resolve_include_path(path: str) -> str:
            if not os.path.isabs(path):
                # Make relative path absolute, handling ../ sequences properly
                path = os.path.normpath(os.path.join(directory, path))
                path = os.path.abspath(path)
            return path
        
        # Convert relative include paths to absolute paths
        enhanced_args = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith("-I"):
                if arg == "-I" and i + 1 < len(args):
                    # Next argument is the include path
                    include_path = resolve_include_path(args[i + 1])
                    i += 2
                else:  # Just the -I flag, no next argument
                    include_path = resolve_include_path(arg[2:])
                    i += 1
                enhanced_args.append(f"-I{include_path}")
            else:
                enhanced_args.append(arg)
                i += 1
        
        # Add additional system include directories
        enhanced_args += [
            "-x", "c++",
            "-I/usr/local/include/x86_64-unknown-linux-gnu/c++/v1",
            "-I/usr/local/include/c++/v1",
            "-I/usr/local/lib/clang/18/include",
            "-I/usr/local/include",
            "-I/usr/include/x86_64-linux-gnu",
            "-I/usr/include",
             "-resource-dir=/usr/local/lib/clang/18",  # explicitly tell clang resource dir
        ]
        # project_include_dirs = [
        #     str(self.project_root / "include"),
        #     str(self.project_root / "src"),
        #     str(self.project_root)
        # ]
        
        # for include_dir in project_include_dirs:
        #     if os.path.exists(include_dir):
        #         enhanced_args.extend(["-I", include_dir])
        
        # Parse with compile_commands.json arguments
        translation_unit = self.index.parse(
            file_path,
            args=enhanced_args,
            options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )
        
        if translation_unit:
            # Check for diagnostics (errors/warnings)
            diagnostics = list(translation_unit.diagnostics)
            if diagnostics:
                severe_errors = [d for d in diagnostics if d.severity >= 3]  # Error or Fatal
                if severe_errors:
                    print(f"Warning: {len(severe_errors)} severe errors in {file_path}")
                    for diag in severe_errors[:3]:  # Show first 3 errors
                        print(f"  {diag.location.file}:{diag.location.line}: {diag.spelling}")
                    if len(severe_errors) > 3:
                        print(f"  ... and {len(severe_errors) - 3} more errors")
            
            self._traverse_ast(translation_unit.cursor)
        else:
            print(f"Error: Failed to create translation unit for {file_path}")
                
        # except Exception as e:
            # print(f"Error parsing {file_path}: {e}")
    
    def load_compile_commands(self, compile_db_path: str) -> Dict[str, tuple]:
        """Load compile_commands.json or create simple compilation args"""
        compile_db = {}
        
        if not os.path.exists(compile_db_path):
            # If no compile_commands.json, create simple args for common files
            print(f"Warning: {compile_db_path} not found. Using default compilation args.")
            return compile_db
        
        try:
            with open(compile_db_path, 'r') as f:
                commands = json.load(f)
            
            for cmd in commands:
                directory = cmd.get('directory', '')
                file_path = cmd.get('file', '')
                
                # Parse command or arguments
                if 'command' in cmd:
                    import shlex
                    args = shlex.split(cmd['command'])[1:]  # Skip compiler name
                else:
                    args = cmd.get('arguments', [])[1:]  # Skip compiler name
                
                # Clean up args - remove fuzzer-specific flags and output files
                cleaned_args = []
                skip_next = False
                for arg in args:
                    if skip_next:
                        skip_next = False
                        continue
                    if arg in ['-o', '--output']:
                        skip_next = True
                        continue
                    if any(skip in arg for skip in ['fuzzer', 'sanitize', 'FUZZING']):
                        continue
                    if arg.endswith('.o'):  # Skip object files
                        continue
                    cleaned_args.append(arg)

                compile_db[file_path] = (directory, cleaned_args[:-1])  # Exclude last arg if it's an input file

        except Exception as e:
            print(f"Error loading compile_commands.json: {e}")
        
        return compile_db

    def process_project(self, compile_db_path: str):
        """Process all files from compile_commands.json"""
        compile_db = self.load_compile_commands(compile_db_path)
        
        for src_file in compile_db:
            directory, args = compile_db[src_file]
            self.analyze_file(directory, src_file, args)
    
    
    def export_to_json(self, output_path: str):
        """Export functions to JSON"""
        functions_list = [asdict(func) for func in self.extracted_functions.values()]
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(functions_list, f, indent=2, ensure_ascii=False)
        
        print(f"Exported {len(functions_list)} functions to {output_path}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract C++ functions using compile_commands.json')
    parser.add_argument('-p','--project-root', help='Project root directory', default='/src/ada-url')
    parser.add_argument('-c', '--compile-commands', default='/src/ada-url/compile_commands.json',
                       help='Path to compile_commands.json')
    parser.add_argument('-o', '--output', default='functions.json',
                       help='Output JSON file')
    
    args = parser.parse_args()
    
    # Create extractor
    extractor = LibclangFunctionExtractor(args.project_root)
    # Process project
    extractor.process_project(args.compile_commands)
    
    # Export results
    extractor.export_to_json(args.output)

if __name__ == '__main__':
    main()
