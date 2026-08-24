













from copy import deepcopy
from typing import TYPE_CHECKING, AsyncGenerator, Dict, Union

if TYPE_CHECKING:
    from ...types import ChatCompletion, ChatCompletionChunk


class HarmonyStreamParser:
    def __init__(self):

        self.current_channel = None

        self.buffer = ""

    def feed(self, text):
        ''











        segments = []


        if self.current_channel == "analysis":

            self.buffer += text
            if "assistantfinal" in self.buffer:

                before, after = self.buffer.split("assistantfinal", 1)
                if before:
                    segments.append({"channel": "analysis", "content": before})

                self.current_channel = "final"
                self.buffer = ""
                if after:
                    segments.append({"channel": "final", "content": after})
                return segments
            else:

                if any(
                    self.buffer.endswith("assistantfinal"[:i])
                    for i in range(1, len("assistantfinal") + 1)
                ):

                    return segments
                else:

                    if self.buffer:
                        segments.append({"channel": "analysis", "content": self.buffer})
                        self.buffer = ""
                    return segments


        if self.current_channel == "final":

            if text.startswith("analysis"):

                self.current_channel = None
                self.buffer = ""

                return self.feed(text)
            else:
                segments.append({"channel": "final", "content": text})
                return segments


        if text.startswith("analysis"):
            self.current_channel = "analysis"
            rest = text[len("analysis") :]
            if "assistantfinal" in rest:

                before, after = rest.split("assistantfinal", 1)
                if before:
                    segments.append({"channel": "analysis", "content": before})
                self.current_channel = "final"
                if after:
                    segments.append({"channel": "final", "content": after})
            else:

                self.buffer = rest

                if any(
                    self.buffer.endswith("assistantfinal"[:i])
                    for i in range(1, len("assistantfinal") + 1)
                ):

                    pass
                else:

                    if self.buffer:
                        segments.append({"channel": "analysis", "content": self.buffer})
                        self.buffer = ""
        elif text.startswith("assistantfinal"):
            self.current_channel = "final"
            rest = text[len("assistantfinal") :]
            if rest:
                segments.append({"channel": "final", "content": rest})

        return segments


async def async_stream_harmony_chat_completion(
    chunks: Union[
        "ChatCompletion",
        AsyncGenerator["ChatCompletionChunk", None],
    ],
) -> AsyncGenerator["ChatCompletion", None]:
    ''







    if isinstance(chunks, dict) and chunks.get("object") == "chat.completion":
        out_data = deepcopy(chunks)

        for choice in out_data["choices"]:
            parser = HarmonyStreamParser()
            msg = choice["message"]


            original_content = msg.get("content") or ""
            original_reasoning = msg.get("reasoning_content") or ""


            msg["content"] = ""
            msg["reasoning_content"] = ""
            msg.setdefault("tool_calls", [])


            for seg in parser.feed(original_content):
                ch, c = seg["channel"], seg["content"]
                if ch == "final":
                    msg["content"] += c
                elif ch == "analysis":
                    msg["reasoning_content"] += c
                elif ch == "tool":
                    msg["tool_calls"].append(c)


            for seg in parser.feed(original_reasoning):
                if seg["channel"] == "analysis":
                    msg["reasoning_content"] += seg["content"]
                elif seg["channel"] == "tool":
                    msg["tool_calls"].append(seg["content"])


            if not msg["reasoning_content"] and not original_reasoning:
                msg["reasoning_content"] = None  # type: ignore

        yield out_data

    else:

        parsers_per_choice = {}

        async for chunk in chunks:  # type: ignore
            out_chunk = {  # type: ignore
                "id": chunk["id"],
                "model": chunk["model"],
                "object": chunk["object"],
                "created": chunk["created"],
                "choices": [],
            }

            for i, choice in enumerate(chunk["choices"]):
                delta = choice.get("delta", {})
                text = delta.get("content") or ""  # type: ignore

                if i not in parsers_per_choice:
                    parsers_per_choice[i] = HarmonyStreamParser()


                curr_delta: Dict[str, object] = {
                    "content": "",
                    "reasoning_content": "",
                    "tool_calls": [],
                }

                for seg in parsers_per_choice[i].feed(text):
                    ch = seg["channel"]
                    c = seg["content"]
                    if ch == "final":
                        curr_delta["content"] += c  # type: ignore
                    elif ch == "analysis":
                        curr_delta["reasoning_content"] += c  # type: ignore
                    elif ch == "tool":
                        curr_delta["tool_calls"].append(c)  # type: ignore

                if curr_delta["reasoning_content"]:
                    if not curr_delta["content"]:
                        curr_delta["content"] = None

                elif curr_delta["content"]:
                    if not curr_delta["reasoning_content"]:
                        curr_delta["reasoning_content"] = None

                elif (
                    choice.get("finish_reason") is not None
                    and not curr_delta["reasoning_content"]
                ):


                    curr_delta["reasoning_content"] = None

                out_chunk["choices"].append(  # type: ignore
                    {
                        "index": i,
                        "delta": curr_delta,
                        "finish_reason": choice.get("finish_reason"),
                    }
                )


            has_content = any(
                choice["delta"].get("content")  # type: ignore
                or choice["delta"].get("reasoning_content")  # type: ignore
                or choice.get("finish_reason") is not None  # type: ignore
                for choice in out_chunk["choices"]  # type: ignore
            )
            if has_content:
                yield out_chunk  # type: ignore
