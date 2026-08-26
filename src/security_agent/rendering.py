"""Putting untrusted text into Markdown without letting it become Markdown.

Everything the model writes is a summary of code somebody else wrote, and that
somebody is the person whose change is under review. A finding title, a search
description, a rejected claim's reason — each can carry whatever they chose. It
has already gone wrong here: five of six report sections once interpolated
model text raw, so a title could close a `<details>`, open a script tag, or add
a column to a table.

These two functions are the answer, and there are two because the containment
rules inside a code span and outside one are opposites — a backslash escapes in
prose and is literal inside backticks, so using the wrong one silently fails to
contain anything.

They live in their own module because more than one thing renders now: the
report a person reads after a completed review, and the crash trace they read
after one that was killed. A second implementation of an escaping rule is a
second thing to get right, and the copy that gets used less is the copy that
drifts.
"""

from __future__ import annotations


def plain(text: str) -> str:
    """Model-written prose, rendered as text rather than as Markdown.

    Escaping the characters that start a construct — rather than stripping them
    — keeps the sentence readable while ensuring it renders as one paragraph
    and not as a heading, a list, a table, a fence, or an HTML tag.
    """
    text = " ".join((text or "").split())
    # Only the inline constructs. Headings, lists, tables and fences all need
    # the start of a line, and this text is collapsed to one line that always
    # follows other content — so escaping `#`, `|`, `*` and `_` would buy no
    # safety and would turn every `get_user` into `get\\_user`, which is worse
    # to read and breaks anything grepping the report.
    #
    # That reasoning has one precondition, and it is the caller's to keep: the
    # result must never be placed at the start of a line, and never inside a
    # table cell — `|` is deliberately not escaped, which is right for a
    # paragraph and wrong for a cell.
    for character in ("\\", "`", "<", ">", "[", "]"):
        text = text.replace(character, "\\" + character)
    return text


def code_span(text: str) -> str:
    """A path or identifier rendered inline, that cannot end its own span.

    `plain` is wrong here: inside a code span a backslash is a literal
    backslash, not an escape, so escaping would both fail to contain the text
    and put visible slashes in the path. CommonMark ends a span only on a
    backtick run at least as long as the opening one, so the delimiter is made
    one longer than the longest run inside. A span whose content begins or ends
    with a backtick needs one space of padding, which the reader does not see.
    """
    text = " ".join((text or "").split())
    longest = 0
    run = 0
    for character in text:
        run = run + 1 if character == "`" else 0
        longest = max(longest, run)
    if not longest:
        return "`{}`".format(text)
    ticks = "`" * (longest + 1)
    return "{} {} {}".format(ticks, text, ticks)
