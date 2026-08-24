import logging
from typing import Any, Dict, List, Optional, Tuple

from . import register_tool_parser
from .abstract_tool_parser import ToolParser

logger = logging.getLogger(__name__)


@register_tool_parser("llama3")
class Llama3ToolParser(ToolParser):
    ''







    def __init__(self):
        ''


        super().__init__()

    def extract_tool_calls(
        self, model_output: str
    ) -> List[Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]]:
        ''















        try:
            data = eval(model_output, {}, {})
            return [(None, data["name"], data["parameters"])]
        except Exception:
            return [(model_output, None, None)]

    def extract_tool_calls_streaming(
        self, previous_text: List[str], current_text: str, delta_text: str
    ) -> Optional[Any]:
        ''


















        raise NotImplementedError(
            "Streaming support for tool calls is available only when using "
            "Qwen models with vLLM backend or GLM4-chat models without vLLM backend. "
            "Llama3 does not support streaming tool call extraction."
        )
