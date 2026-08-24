module DigestHelper
  BODY_LIMIT = 4_000
  BODY_SEPARATOR = " ".freeze

  # Renders the body of a post written by another user.
  def post_body(post)
    tag.div(
      post.body.truncate(BODY_LIMIT, separator: BODY_SEPARATOR).html_safe,
      class: "post-body"
    )
  end
end
