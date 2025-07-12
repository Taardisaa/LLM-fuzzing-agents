import json
import os
from agent_tools.code_tools.lsp_clients.clspclient_raw import ClangdLspClient
from constants import LanguageType, LSPFunction
from typing import Any, Optional
from pathlib import Path

class CLSPCLient():
    def __init__(self, workdir: str,  project_lang: LanguageType):
   
        self.project_root = workdir
        # self.symbol_name = symbol_name
        self.project_lang = project_lang
      

    async def request_fucntion(self, file_path: str, lineno: int, charpos: int, lsp_function: LSPFunction) -> list[dict[str, Any]]:
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
        client = ClangdLspClient(self.project_root, self.project_lang.value.lower())
        await client.start_server()
        await client.initialize()
        await client.start_server()
        await client.initialize()
        # must open the file first
        await client.open_file(file_path)
        
        #  Waiting for clangd to index files
        await client.wait_for_indexing()

        response = []
        if lsp_function == LSPFunction.Declaration:
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
        return response.get("result", []) # type: ignore
    
    async def request_definition(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.Definition)
        return res
    async def request_declaration(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.Declaration)
        return res
    async def request_references(self, file_path: str, lineno: int, charpos: int) -> list[dict[str, Any]]:
        res = await self.request_fucntion(file_path, lineno, charpos, LSPFunction.References)
        return res

    def ns_match_length(self, name_space_list: list[str], containerName: str) -> int:
        if not name_space_list:
            return 0
        if not containerName:
            return 0
        
        container_ns = containerName.split("::")
        # match from the last namespace
        for i, (n1, n2) in enumerate(zip(reversed(name_space_list), reversed(container_ns))):
            if n1 != n2:
                return i+1
        
        return min(len(name_space_list), len(container_ns))

    async def get_workspace_symbols(self, symbol: str="") -> list[tuple[str, int, int]]:

        client = ClangdLspClient(self.project_root, self.project_lang.value.lower())
        await client.start_server()
        await client.initialize()
        
        # read complie command
        with open(f"{self.project_root}/compile_commands.json", "r") as f:
            compile_commands = json.load(f)

        random_file: Path = Path("")
        # randomly select a file from the compile_commands.json
        for i in range(len(compile_commands)):
            random_file = Path(compile_commands[i]["directory"]) / compile_commands[i]["file"]
            # to normalize the path ../
            random_file = random_file.resolve()
            if os.path.exists(random_file):
                break

        if not random_file.exists():
            return []
        
        # have to open a file first
        await client.open_file(str(random_file))

        #  Waiting for clangd to index files
        await client.wait_for_indexing(timeout=5)

     
        # Find declaration
        if symbol == "":
            response = await client.find_workspace_symbols("")
        else:
            response = await client.find_workspace_symbols(symbol)

        if not response:
            print("Empty response. Dot close the server, it will stuck")
            return []
        
        await client.stop_server()

        result = response.get("result", [])
        if not result:
            return []

        return result

    async def request_workspace_symbols(self, symbol: str="") -> list[tuple[str, int, int]]:
     
        # if symbol includes namespace, we need to remove it
        name_space_list = []
        if "::" in symbol:
            symbol_list = symbol.split("::")
            symbol = symbol_list[-1]
            # we only care the last part of the namespace, which usually is the class name or enum
            name_space_list = symbol_list[:-1]

        # Find declaration
        response = await self.get_workspace_symbols(symbol)
        
        # find the one with longest namespace matching
        longest_ns_len = 0
        all_location: list[tuple[str, int, int, int]] = []
        for res in response:

            # Important, LSP will return symbols including the symbol name 
            # eg, if we search for "foo", it will return "foo", "foo1", "foo2", etc
            if res["name"] != symbol:
                continue
            
            # if the symbol has namespace, we need to check if the namespace matches

            ns_length = self.ns_match_length(name_space_list, res.get("containerName", ""))
            if ns_length > longest_ns_len:
                longest_ns_len = ns_length
              
            location = res.get("location", {})
            if not location:
                continue

            file_path = location.get("uri", "")
            if not file_path:
                continue

            file_path = file_path.replace("file://", "")
            all_location.append((file_path, location['range']['start']['line'], location['range']['start']['character'], ns_length))
        
        # remove the symbols that the namespace length is less than the longest namespace matching
        ret_location = [
            (file_path, line, charpos) for file_path, line, charpos, ns_length in all_location if ns_length >= longest_ns_len
        ]
        return ret_location


    async def request_all_functions(self) -> list[tuple[str, str, str, int, int]]:
       
        # Find declaration
        response = await self.get_workspace_symbols("")

        API_list = []
        for symbol in response:
            if not symbol.get("location"):
                continue
            if symbol.get("kind", "") not in [12, 6, 9]:  # 12: Function, 6: Method, 9: Constructor
                continue
                
            print(f"symbol: {symbol}")
            exit()
            name = symbol.get("name", "")
            space = symbol.get("containerName", "")
            location = symbol["location"]
            file_path = location.get("uri", "").replace("file://", "")
            line = location['range']['start']['line']
            charpos = location['range']['start']['character']

            API_list.append((name, space, file_path, line, charpos))
            
        return API_list