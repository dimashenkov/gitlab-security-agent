module ApplicationHelper
  def initials(name)
    name.to_s.split.map { |part| part[0] }.join
  end
end
