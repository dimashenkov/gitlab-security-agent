module ApplicationHelper
  def posted_at(time)
    time.strftime("%-d %b %Y")
  end
end
