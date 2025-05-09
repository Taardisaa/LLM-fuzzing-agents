import os
from enum import Enum

PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
# print(PROJECT_PATH)

ALL_FILE_EXTENSION = ["c", "cpp", "java", "py", "cc", "cxx"]
ALL_HEADER_EXTENSION = ["h", "hpp", "hh"]

class LSPResults(Enum):
    """Results of Language Server Protocol."""
    Success = "success"
    Error = "error"
    Retry = "retry"
    NoResult = "no result"
    DockerError = "docker error"

class DockerResults(Enum):
    Success = "success"
    Error = "docker error"

class Retriever(Enum):
    LSP = "lsp"
    Parser = "parser"
    Mixed = "mixed"


class LanguageType(Enum):
    """File types of target files."""
    C = 'C'
    CPP = 'CPP'
    JAVA = 'Java'
    NONE = ''

class LSPFunction(Enum):
    Definition = "definition"
    Declaration = "declaration"
    References = "references"
    Header = "header"

class CompileResults(Enum):
    Success = "Complie Success"
    CodeError = "Compile Error"
    FuzzerError = "No Fuzzer"
    ImageError = "Build Image Error"


class FuzzResult(Enum):
    NoError = "No Error"
    Crash = "Crash"
    RunError = "Run Error"
    ReadLogError = "Read Log Error"
    ConstantCoverageError = "Constant Coverage Error"
    LackCovError = "Lack initial coverage or the final done coverage"


class ToolDescMode(Enum):
    Simple = "simple"
    Detailed = "detailed"


class CodeSearchAPIName(Enum):
    """APIs for searching code snippets."""
    Github = "Github"
    # Google = "Google"
    # Bing = "Bing"
    # StackOverflow = "StackOverflow"
    # CodeSearch = "CodeSearch"
    # 
# Entry function for fuzzing.
FuzzEntryFunctionMapping: dict[LanguageType, str] = {
    LanguageType.C: "LLVMFuzzerTestOneInput",
    LanguageType.CPP: "LLVMFuzzerTestOneInput",
    LanguageType.JAVA: "fuzzerTestOneInput",
}

COV_WRAP_FILE_NAME = "cov_wrap_code"
# # Pydantic
