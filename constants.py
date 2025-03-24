import os

PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
# print(PROJECT_PATH)

ALL_FILE_EXTENSION = ["c", "cpp", "java", "py", "cc", "cxx"]
ALL_HEADER_EXTENSION = ["h", "hpp", "hh"]

class LSPResults():
    """Results of Language Server Protocol."""
    Success = "success"
    Error = "error"
    Retry = "retry"
    NoResult = "no result"
    DockerError = "docker error"

class DockerResults():
    Success = "success"
    Error = "docker error"

class Retriever:
    LSP = "lsp"
    Parser = "parser"
    Mixed = "mixed"


class LanguageType():
    """File types of target files."""
    C = 'C'
    CPP = 'CPP'
    JAVA = 'Java'
    NONE = ''

class LSPFunction():
    Definition = "definition"
    Declaration = "declaration"
    References = "references"
    Header = "header"

class CompileResults:
    Success = "Complie Success"
    CodeError = "Compile Error"
    FuzzerError = "No Fuzzer"
    ImageError = "Build Image Error"


class FuzzResult:
    NoError = "No Error"
    Crash = "Crash"
    RunError = "Run Error"
    ReadLogError = "Read Log Error"
    ConstantCoverageError = "Constant Coverage Error"
    LackCovError = "Lack initial coverage or the final done coverage"


class ToolDescMode():
    Simple = "simple"
    Detailed = "detailed"


class CodeSearchAPIName():
    """APIs for searching code snippets."""
    Github = "Github"
    # Google = "Google"
    # Bing = "Bing"
    # StackOverflow = "StackOverflow"
    # CodeSearch = "CodeSearch"
    # 
# Entry function for fuzzing.
FuzzEntryFunctionMapping = {
    LanguageType.C: "LLVMFuzzerTestOneInput",
    LanguageType.CPP: "LLVMFuzzerTestOneInput",
    LanguageType.JAVA: "fuzzerTestOneInput",
}

# # Pydantic
