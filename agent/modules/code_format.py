from langchain_core.language_models import BaseChatModel
from pydantic import BaseModel, Field
import re
import tiktoken
from utils.proto import AcceptedLLM


class CodeAnswerStruct(BaseModel):
    """Split the answer into the content before the code, the code, and the content after the code."""
    before_code: str = Field(description="The unnecessary explanation before the code.")
    source_code: str = Field(description="The harness code part of the answer.")
    after_code: str = Field(description="The unnecessary explanation after the code.")


class CodeFormatTool():

    def __init__(self, llm: AcceptedLLM, prompt: str):
        self.llm = llm
        self.prompt = prompt

    def extract_code(self, response: str) -> str:
        '''Extract the code from the response with LLM'''

        extract_prompt = self.prompt.format(response=response)
        enc = tiktoken.encoding_for_model("gpt-4o")
        if len(enc.encode(extract_prompt)) > 2000:
            # remove the first line until the error message is short enough
            print("Extract prompt is too long, remove the first line.")

        _respsone: CodeAnswerStruct = self.llm.invoke(extract_prompt)   # type: ignore
        source_code = _respsone.source_code 
        # deal with the new line
        # if "\\n" in source_code:
            # source_code = source_code.replace("\\n", "\n")

        # remove the line number if exists
        source_code = re.sub(r'^//\s+\d+:\s?', '', source_code, flags=re.MULTILINE)
        # remove some useless string
        source_code = source_code.replace("```cpp", "")
        source_code = source_code.replace("```", "")
        # if source_code and source_code.startswith("c\n"):
            # source_code = source_code[1:]
        return source_code
