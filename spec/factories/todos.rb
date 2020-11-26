# frozen_string_literal: true

FactoryBot.define do
  factory :todo do
    title { Faker::Lorem.word }
    created_by { 1 }
  end
end
