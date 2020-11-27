require 'rails_helper'

# Test suite for user model
RSpec.describe User, type: :model do
  # Association test
  it { should have_many(:todos).dependent(:destroy) }

  # Validation test
  # ensure email and password are present
  it { should validate_presence_of(:email) }
  it { should validate_presence_of(:password) }
end
