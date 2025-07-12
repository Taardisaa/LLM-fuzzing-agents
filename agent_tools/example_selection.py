from langchain_openai import ChatOpenAI
from constants import PROJECT_PATH
from pathlib import Path
from pydantic import BaseModel, Field

class AnswerStruct(BaseModel):
    """Split the response into the answer and the explaintion."""
    answer: str = Field(description="The answer to the question.")
    explaination: str = Field(description="The explanation for the answer.")


class LLMSelector:
    def __init__(self, model_name: str):
        self.name = "LLM"
        self.structured_llm = ChatOpenAI(model=model_name, temperature=0.).with_structured_output(AnswerStruct) # type: ignore
        prompt_path = Path(f"{PROJECT_PATH}/prompts/example_selection.txt")
        self.prompt_template = prompt_path.read_text()


    def score_example(self, target_function: str, code: str) -> int:

        prompt = self.prompt_template.replace("{target_function}", target_function).replace("{code}", code)
        resp = self.structured_llm.invoke(prompt) # type: ignore
        # print(f"target function: {target_function}, code: {code}")
        # print(f"answer: {resp.answer}, explaination: {resp.explaination}")
        # time.sleep(1)
       
        if resp.answer.lower() == "true": # type: ignore
            return 1
        else:
            return 0

if __name__ == "__main__":
    llm = LLMSelector("gpt-4-0613")
    code = """
int\nLLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    sip_msg_t orig_inv = { };\n    orig_inv.buf = (char*)data;\n    orig_inv.len = size;\n\n    if(size >= 4*BUF_SIZE) {\n        /* test with larger message than core accepts, but not indefinitely large */\n        return 0;\n    }\n\n    if (parse_msg(orig_inv.buf, orig_inv.len, &orig_inv) < 0) {\n        goto cleanup;\n    }\n\n    parse_headers(&orig_inv, HDR_EOH_F, 0);\n\n    parse_sdp(&orig_inv);\n\n    parse_from_header(&orig_inv);\n\n    parse_from_uri(&orig_inv);\n\n    parse_to_header(&orig_inv);\n\n    parse_to_uri(&orig_inv);\n\n    parse_contact_headers(&orig_inv);\n\n    parse_refer_to_header(&orig_inv);\n\n    parse_pai_header(&orig_inv);\n\n    parse_diversion_header(&orig_inv);\n\n    parse_privacy(&orig_inv);\n\n    parse_content_disposition(&orig_inv);\n\n    parse_identityinfo_header(&orig_inv);\n\n    parse_record_route_headers(&orig_inv);\n\n    parse_route_headers(&orig_inv);\n\n    str uri;\n    get_src_uri(&orig_inv, 0, &uri);\n\n    str ssock;\n    get_src_address_socket(&orig_inv, &ssock);\n\ncleanup:\n    free_sip_msg(&orig_inv);\n\n    return 0;\n}
    """

    target_function = """
    int parse_from_header(struct sip_msg *msg)
    """

    print(llm.score_example(target_function, code))