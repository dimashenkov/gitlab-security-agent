class User < ApplicationRecord
  # Columns: email, display_name, theme, density, locale, admin (boolean)
  validates :email, presence: true
end
