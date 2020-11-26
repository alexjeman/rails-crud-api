FactoryBot.define do
  factory :user do
    sequence(:email, 10) { |n| "test-#{n}@example.com" }
    password { 'Password123' }
  end
end
