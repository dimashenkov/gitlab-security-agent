import React from "react";
import clsx from "clsx";

import { toHtml } from "./markdown";

const LAYOUT = {
  wide: "article article--wide",
  narrow: "article article--narrow",
  quoted: "article article--quoted",
};

type Article = { id: string; body: string; layout: keyof typeof LAYOUT };

// Renders an article body written by another user.
export function ArticleBody({ article }: { article: Article }) {
  const html = toHtml(article.body);
  return (
    <article
      className={clsx(LAYOUT[article.layout])}
      data-article-id={article.id}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
