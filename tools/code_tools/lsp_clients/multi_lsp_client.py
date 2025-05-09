from multilspy import LanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger
from constants import LanguageType
import subprocess as sp
from typing import Any

class MultilspyClient:
    def __init__(self, workdir: str, project_lang: LanguageType):
        self.config = MultilspyConfig.from_dict({"code_language": project_lang.value})
        self.logger = MultilspyLogger()
        self.lsp = LanguageServer.create(self.config, self.logger, workdir)
        self.work_dir = workdir

    async def request_definition(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_definition(file_path, lineno, charpos)
        return result
    
    async def request_declaration(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_hover(file_path, lineno, charpos)
        return result
    
    async def request_completions(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_completions(file_path, lineno, charpos)
        return result
    
    async def request_references(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_references(file_path, lineno, charpos)
        return result
    
    async def request_document_symbols(self, file_path: str) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_document_symbols(file_path)
        return result
    
    async def request_hover(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        with self.lsp.start_server():
            result = await self.lsp.request_hover(file_path, lineno, charpos)
        return result
    
    
    async def request_workspace_symbols(self, symbol: str) -> list[tuple[str, int, int]]:

        # first grep the symbol to find the file path
 
        # Execute `find` command to recursively list files and directories
        cmd = f"grep --binary-files=without-match -rnw {self.work_dir} -e  {symbol}"

        results = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT,  text=True)
        output = results.stdout.strip()

        if not output:
            return []

        # the location may be in the comments or in the string literals
        all_lines = output.splitlines()

        # filter some files by file type
        filtered_file: set[str] = set()
        for line in all_lines:
            
            parts = line.split(':', 2)
            # check if the line is valid
            if len(parts) < 3:
                continue

            file_path, _, _ = parts
            # filter the other files (.md, .txt, etc)
            file_type = file_path.split('.')[-1]

            filter_header = [ 'h', 'hpp', 'hh', 'hxx', 'c', 'cc', 'cpp', 'cxx', 'c++',  "java"]

            if file_type not in filter_header:
                continue
            filtered_file.add(file_path)

        file_symbols_dict: dict[str, dict[str, Any]] = {}
        with self.lsp.start_server(): # type: ignore
            for file_path in filtered_file:
                result = await self.lsp.request_document_symbols(file_path)

                if not result:
                    continue

                file_symbols_dict[file_path] = result # type: ignore

        res_symbols:list[tuple[str, int, int]] = []
        for file_path, symbol_list in file_symbols_dict.items():
            
            for symbol_dict in symbol_list:
                if symbol_dict["name"] == symbol:  # type: ignore
                    res_symbols.append((file_path, symbol_dict['selectionRange']['start']['line'], symbol_dict['selectionRange']['end']['character']))  # type: ignore

        return res_symbols