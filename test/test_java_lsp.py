from multilspy import SyncLanguageServer
from multilspy.multilspy_config import MultilspyConfig
from multilspy.multilspy_logger import MultilspyLogger
...
config = MultilspyConfig.from_dict({"code_language": "java"}) # Also supports "python", "rust", "csharp", "typescript", "javascript", "go", "dart", "ruby"
logger = MultilspyLogger()
lsp = SyncLanguageServer.create(config, logger, "/src/commons-jxpath")
with lsp.start_server():
    result = lsp.request_definition(
        "../JXPathFuzzer.java", # Filename of location where request is being made
        47, # line number of symbol for which request is being made
        28 # column number of symbol for which request is being made
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