import React from "react";
import DOMPurify from "dompurify";

import { toHtml } from "./markdown";

const MARKUP = {
  ALLOWED_TAGS: ["p", "br", "em", "strong", "code", "pre", "ul", "ol", "li"],
  ALLOWED_ATTR: [] as string[],
  ALLOW_DATA_ATTR: false,
};

type Article = { id: string; body: string };

// Renders an article body written by another user.
export function ArticleBody({ article }: { article: Article }) {
  const html = DOMPurify.sanitize(toHtml(article.body), MARKUP);
  return (
    <article
      className="article"
      data-article-id={article.id}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
