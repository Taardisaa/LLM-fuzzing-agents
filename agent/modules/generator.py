from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage
import logging
from typing import Callable, Any
from utils.misc import save_code_to_file
from pathlib import Path
from utils.misc import fix_qwen_tool_calls, fix_claude_tool_calls
from langgraph.graph import END # type: ignore
from utils.proto import AcceptedLLM

class HarnessGenerator:
    """Generator node for creating initial fuzz harness code using an LLM.
    
    This class manages the generation of fuzz harness code, handling tool calls,
    code extraction, and validation. It supports iterative refinement through
    tool usage and tracks tool call limits to prevent excessive iterations.
    """
    
    def __init__(self, 
                 runnable: AcceptedLLM, 
                 max_tool_call: int, 
                 continue_flag: bool, 
                 save_dir: Path, 
                 code_callback: Callable[[str], str], 
                 logger: logging.Logger, 
                 model_name: str = ""):
        """Initialize the harness generator.
        
        Args:
            runnable: LLM instance (optionally bound with tools) for code generation
            max_tool_call: Maximum number of tool calls allowed before termination
            continue_flag: If True, prepend initial prompt to generated code
            save_dir: Directory path where generated code drafts are saved
            code_callback: Function to extract/format code from LLM response
            logger: Logger instance for tracking generation progress
            model_name: Name of the model being used (for tool call fixing)
        """
        self.runnable = runnable
        self.save_dir = save_dir
        self.code_callback = code_callback
        self.logger = logger
        self.max_tool_call = max_tool_call
        self.continue_flag = continue_flag
        self.count_tool_call = 0
        self.model_name = model_name
        self.max_retries = 3

    def _handle_tool_call_response(self, response: Any) -> dict[str, Any]:
        """Process response when LLM makes tool calls.
        
        Args:
            response: LLM response containing tool calls
            
        Returns:
            State update dict with messages or END signal if limit exceeded
        """
        self.count_tool_call += len(response.tool_calls)
        
        if self.count_tool_call > self.max_tool_call:
            self.logger.warning(f"Tool call limit exceeded: {self.count_tool_call}/{self.max_tool_call}")
            return {"messages": f"{END}. Initial Generator exceeds max tool call {self.max_tool_call}"}
        
        return {"messages": response}

    def _extract_and_validate_code(self, response: Any, initial_prompt: str) -> dict[str, Any]:
        """Extract code from LLM response and validate it's not empty.
        
        Args:
            response: LLM response containing generated code
            initial_prompt: Initial prompt to prepend if continue_flag is True
            
        Returns:
            State update dict with code and messages, or END signal if code is empty
        """
        source_code = self.code_callback(response.content)

        if not source_code.strip():
            self.logger.warning("Empty code returned from callback")
            return {"messages": f"{END}. Empty code returned, stop generating."}

        # Prepend initial prompt if continue mode is enabled
        full_source_code = initial_prompt + source_code if self.continue_flag else source_code
        
        if not full_source_code.strip():
            self.logger.warning("Full source code is empty after processing")
            return {"messages": f"{END}. Empty code returned, stop generating."}
        
        # Save the generated code draft
        save_code_to_file(full_source_code, self.save_dir / "draft_fix0.txt")
        self.logger.info("Generated draft harness code")
        
        return {
            "messages": ("assistant", source_code), 
            "harness_code": full_source_code, 
            "fix_counter": 0
        }

    def respond(self, state: dict[str, Any]) -> dict[str, Any]:
        """Generate fuzz harness code from the current state.
        
        This method invokes the LLM with the conversation history, handles tool calls,
        extracts generated code, and updates the state accordingly. It includes retry
        logic for handling invalid tool calls and enforces tool call limits.
        
        Args:
            state: Current agent state containing messages and other context
            
        Returns:
            Updated state dict with one of:
            - New tool call messages if LLM requests tool usage
            - Generated harness code if LLM produces code
            - END signal if errors occur or limits are exceeded
        """
        response = None
        
        # Retry loop for handling transient failures or invalid tool calls
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.runnable.invoke(state["messages"])
                
                # Fix invalid tool calls based on model type
                if hasattr(response, 'invalid_tool_calls') and response.invalid_tool_calls: # type: ignore
                    self.logger.warning(f"Invalid tool calls detected (attempt {attempt}/{self.max_retries})")
                    
                    if self.model_name.startswith("anthropic"):
                        response = fix_claude_tool_calls(response)
                    else:
                        response = fix_qwen_tool_calls(response)
                
                # If we got a valid response, break out of retry loop
                if response:
                    break
                    
            except Exception as e:
                self.logger.error(f"LLM invocation failed (attempt {attempt}/{self.max_retries}): {e}")
                if attempt == self.max_retries:
                    return {"messages": f"{END}. LLM invocation failed after {self.max_retries} attempts."}
        
        # If all retries failed
        if not response:
            self.logger.error("Failed to get valid response after all retries")
            return {"messages": f"{END}. Wrong tool call, stop generating."}
       
        # Handle tool calls
        if len(response.tool_calls) != 0:   # type: ignore
            return self._handle_tool_call_response(response)
        
        # Extract and validate generated code
        initial_prompt = state["messages"][0].content
        return self._extract_and_validate_code(response, initial_prompt)

