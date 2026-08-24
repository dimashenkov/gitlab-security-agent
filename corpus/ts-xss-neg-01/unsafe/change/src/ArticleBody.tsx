import React from "react";
import DOMPurify from "dompurify";

import { toHtml } from "./markdown";

const MARKUP = {
  ALLOWED_TAGS: ["p", "br", "em", "strong", "code", "pre", "ul", "ol", "li"],
  ALLOWED_ATTR: [] as string[],
  ALLOW_DATA_ATTR: false,
};

type Article = { id: string; body: string; standfirst: string };

// Renders an article written by another user: the standfirst as a line of
// text, then the body the author submitted as markdown.
export function ArticleBody({ article }: { article: Article }) {
  const standfirst = DOMPurify.sanitize(article.standfirst, MARKUP);
  const html = toHtml(article.body);
  return (
    <article className="article" data-article-id={article.id}>
      <p className="article__standfirst">{standfirst}</p>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </article>
  );
}
