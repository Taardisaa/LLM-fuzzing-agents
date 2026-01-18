from langchain_core.runnables import Runnable
from langchain_core.language_models import LanguageModelInput
from langchain_core.messages import AIMessage
from typing import Optional, Union
from langchain_core.language_models import BaseChatModel
# from langchain_openai import _DictOrPydantic
from typing import TypeVar, TypeAlias, Any
from pydantic import BaseModel
from typing import Union
from pathlib import Path


ToolLLM = Runnable[LanguageModelInput, AIMessage]
BM = TypeVar("BM", bound=BaseModel)
DictOrPydanticClass: TypeAlias = dict[str, Any] | type[BM] | type
DictOrPydantic: TypeAlias = dict | BM
StructuredLLM = Runnable[LanguageModelInput, DictOrPydantic]
AcceptedLLM = ToolLLM | BaseChatModel | StructuredLLM

PathLike = Union[str, Path]