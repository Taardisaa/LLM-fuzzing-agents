import json
import os
import subprocess as sp
from tools.code_tools.lsp_clients.clspclient_raw import ClangdLspClient
from constants import LanguageType, LSPFunction, LSPResults


class CLSPCLient():
    def __init__(self, workdir: str,  project_lang: LanguageType):
   
        self.project_root = workdir
        # self.symbol_name = symbol_name
        self.project_lang = project_lang
      

    async def request_fucntion(self, file_path: str, lineno: int, charpos: int, lsp_function: LSPFunction) -> list[dict]:
        """
        Find the definition of a symbol in a C or C++ file using Clangd LSP.
        Args:
            file_path (str): The C++ source file including the symbol.
            lineno (int): The line number where the symbol is located.
            charpos (int): The character position within the line where the symbol is located.
        Returns:
            list[dict]: The list of source code and corresponding file.
        Raises:
            Exception: If there is an error during the request to the LSP server.
        """
        # cpp for C++
        client = ClangdLspClient(self.project_root, self.project_lang.lower())
        await client.start_server()
        await client.initialize()
        await client.start_server()
        await client.initialize()
        # must open the file first
        await client.open_file(file_path)
        
        #  Waiting for clangd to index files
        await client.wait_for_indexing()

        if lsp_function == LSPFunction.Header:
              # Find declaration
            response = await client.find_declaration(
                file_path,
                line=lineno,  
                character=charpos
            )
            if not response:
                return []

            await client.stop_server()
            result = response.get("result", [])
            return result


        elif lsp_function == LSPFunction.Declaration:
            # Find declaration
            response = await client.find_declaration(
                file_path,
                line=lineno,  
                character=charpos
            )

        elif lsp_function == LSPFunction.Definition:
            # Find definition
            response = await client.find_definition(
                file_path,
                line=lineno,
                character=charpos
            )
        elif lsp_function == LSPFunction.References:
            
            # Fisrt jump to definition
            response = await client.find_references(
                file_path,
                line=lineno,
                character=charpos
            )
        if not response:
            return []
        await client.stop_server()

        # to keep the same format as multi_lsp_client.py
        return response.get("result", [])
    
    async def request_definition(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.Definition)
        return res
    async def request_declaration(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.Declaration)
        return res
    async def request_references(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.References)
        return res
    async def request_header(self, file_path: str, lineno: int, charpos: int) -> list[dict]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.Header)
        return res

    async def request_workspace_symbols(self, symbol) -> list[tuple[str, int, int]]:
     
        client = ClangdLspClient(self.project_root, self.project_lang.lower())
        await client.start_server()
        await client.initialize()
        
        # read complie command
        with open(f"{self.project_root}/compile_commands.json", "r") as f:
            compile_commands = json.load(f)

        # randomly select a file from the compile_commands.json
        for i in range(len(compile_commands)):
            random_file = os.path.join(compile_commands[i]["directory"], compile_commands[i]["file"])
            random_file = os.path.abspath(random_file)
            if os.path.exists(random_file):
                break

        if not os.path.exists(random_file):
            return []
        
        # have to open a file first
        await client.open_file(random_file)

        #  Waiting for clangd to index files
        await client.wait_for_indexing(timeout=5)

        # Find declaration
        response = await client.find_workspace_symbols(symbol)

        if not response:
            print("Empty response. Dot close the server, it will stuck")
            return []
        
        await client.stop_server()

        result = response.get("result", [])
        if not result:
            return []
        
        all_location = []
        for res in result:

            # Important, LSP will return symbols including the symbol name 
            # eg, if we search for "foo", it will return "foo", "foo1", "foo2", etc
            if res["name"] != symbol:
                continue

            location = res.get("location", {})
            if not location:
                continue

            file_path = location.get("uri", "")
            if not file_path:
                continue

            file_path = file_path.replace("file://", "")
            all_location.append((file_path, location['range']['start']['line'], location['range']['start']['character']))

        return all_location



