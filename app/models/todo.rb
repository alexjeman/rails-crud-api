class Todo < ApplicationRecord
  # Model association
  belongs_to :user
  has_many :items, dependent: :destroy

  # Validation
  validates_presence_of :title
end
