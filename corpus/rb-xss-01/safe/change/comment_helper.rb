module CommentHelper
  # Renders a comment body written by another user.
  def comment_body(comment)
    tag.div(comment.body, class: "comment-body")
  end
end
