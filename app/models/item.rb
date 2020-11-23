class Item < ApplicationRecord
  # Model associations
  belongs_to :todo

  # Validations
  validates_presence_of :name
end
