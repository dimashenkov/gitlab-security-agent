module DigestHelper
  BODY_TAGS = %w[p br em strong code pre ul ol li a].freeze
  BODY_ATTRIBUTES = %w[href title].freeze

  # Renders the body of a post written by another user.
  def post_body(post)
    tag.div(
      sanitize(post.body, tags: BODY_TAGS, attributes: BODY_ATTRIBUTES).html_safe,
      class: "post-body"
    )
  end
end
