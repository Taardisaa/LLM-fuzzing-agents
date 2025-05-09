from multilspy import SyncLanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger
...
config = MultilspyConfig.from_dict({"code_language": "cpp"}) # Also supports "python", "rust", "csharp", "typescript", "javascript", "go", "dart", "ruby"
logger = MultilspyLogger()
lsp = SyncLanguageServer.create(config, logger, "/src/cjson")
with lsp.start_server():
    result = lsp.request_definition(
        "./fuzzing/cjson_read_fuzzer.c", # Filename of location where request is being made
        46, # line number of symbol for which request is being made
        27 # column number of symbol for which request is being made
    )

    print(result)
    # result2 = lsp.request_completions(
    #     ...
    # )
    # result3 = lsp.request_references(
    #     ...
    # )
    # result4 = lsp.request_document_symbols(
    #     ...
    # )
    # result5 = lsp.request_hover(
    #     ...
    # )
    # ...