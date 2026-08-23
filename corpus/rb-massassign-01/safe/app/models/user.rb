class User < ApplicationRecord
  # Columns: email, display_name, admin (boolean, default false)
  validates :email, presence: true
end
