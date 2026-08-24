module DigestHelper
  BODY_TAGS = %w[p br em strong code pre ul ol li a].freeze
  BODY_ATTRIBUTES = %w[href title].freeze
  SUMMARY_LIMIT = 280
  SUMMARY_SEPARATOR = " ".freeze

  # Renders a post written by another user: a one-line summary above the
  # markup the author submitted.
  def post_body(post)
    snippet = post.body.truncate(SUMMARY_LIMIT, separator: SUMMARY_SEPARATOR)
    markup = sanitize(snippet, tags: BODY_TAGS, attributes: BODY_ATTRIBUTES)
    tag.div(
      tag.p(markup, class: "post-summary") + post.body.html_safe,
      class: "post-body"
    )
  end
end
