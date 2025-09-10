import logging
from typing import Any
from pathlib import Path
from langgraph.graph import END # type: ignore
from constants import LanguageType
from typing import Any
from agent_tools.fuzz_tools.run_fuzzer import FuzzerRunner
from constants import FuzzResult

FUZZMSG = {
    FuzzResult.ConstantCoverageError: "The above code can be built successfully but its fuzzing seems not effective since the coverage never change. Please make sure the fuzz data is used.",
    FuzzResult.ReadLogError: "The above code can be built successfully but it generates a extreme large log which indicates the fuzz driver may include some bugs. Please do not print any information. ",
    FuzzResult.LackCovError: "The above code can be built successfully but its fuzzing seems not effective since it lack the initial or final code coverage info. Please make sure the fuzz data is used.",
}
class FuzzerWraper(FuzzerRunner):
    def __init__(self, oss_fuzz_dir: Path, new_project_name: str,
                 project_lang: LanguageType, run_timeout: int , 
                 save_dir: Path, logger: logging.Logger):

        super().__init__(oss_fuzz_dir, new_project_name, project_lang, run_timeout, save_dir)
        self.logger = logger

        
    def run_fuzzing(self, state: dict[str, Any]) -> dict[str, Any]: # type: ignore
        fix_counter = state.get("fix_counter", 0)
        fuzzer_name = state.get("fuzzer_name", "")

        self.logger.info(f"Run {fix_counter}th Fuzzer for {self.new_project_name}:{fuzzer_name}")
       
        fuzz_res, error_type_line, stack_list = super().run_fuzzing(fix_counter, fuzzer_name)
        
        self.logger.info(f"Fuzz res:{fuzz_res}, {error_type_line} for {self.new_project_name}:{fuzzer_name}")
    
        # unable to fix the code
        if fuzz_res == FuzzResult.RunError:
            return {"messages": ("user", END + "Run Error")}
        elif fuzz_res in [FuzzResult.ConstantCoverageError, FuzzResult.LackCovError,  FuzzResult.ReadLogError]:
            return {"messages": ("user", fuzz_res), "fuzz_msg": FUZZMSG.get(fuzz_res, "")}
        elif fuzz_res == FuzzResult.Crash:
            # extract the first error message
            error_type = error_type_line[0] if len(error_type_line) > 0 else "Unknown Crash, Unable to extract the error message"
            first_stack = stack_list[0] if len(stack_list) > 0 else ["Unknown Crash, Unable to extract the stack trace"]
            fuzz_error_msg = error_type + "\n" + "\n".join(first_stack)
            return {"messages": ("user", fuzz_res), "fuzz_msg": fuzz_error_msg}
        else:
            return {"messages": ("user", fuzz_res)}


