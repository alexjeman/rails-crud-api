# Rails 6 REST API with authentication example

## Implementation
- [JWT authentication branch](https://github.com/alexjeman/rails-crud-api/tree/jwt_authentication)
- [Devise JWT branch (Merged with master)](https://github.com/alexjeman/rails-crud-api/tree/devise_jwt)

## Readme Instructions
- [JWT authentication instruction](https://github.com/alexjeman/rails-crud-api#add-jwt-authentication)
- [Devise JWT instructions](https://github.com/alexjeman/rails-crud-api#add-devise-jwt-authentication)
- [RSpec models tests instructions](https://github.com/alexjeman/rails-rest-api#rspec-model-tests)
- [RSpec controllers tests instructions](https://github.com/alexjeman/rails-rest-api#rspec-controllers-tests)

### New --api app
```
rails new demo-api --api
```

### Setup dotenv
```
gem 'dotenv'
```

### require dotenv in config/application.rb
```
require 'dotenv/load'
```

### Setup CORS config/application.rb
```
gem 'rack-cors'
```

### Add CORS settings to config/application.rb
```
module RailsCrudApi
  class Application < Rails::Application
    # [...]
    
    # CORS
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins '*'
        resource '*', headers: :any, methods: %i[get post patch put]
      end
    end

    # [...]
  end
end
```

### Create Todo model
```
rails g model Todo title:string user:references
```

### Create Item model. By adding todo:references we’re telling the generator to set up an association with the Todo model.
```
rails g model Item name:string done:boolean todo:references
```

### Run migrations
```
rails db:migrate
```

### Create controllers
```
rails g controller Todos
rails g controller Items
```

# Item validations and associations app/models/item.rb
```
class Item < ApplicationRecord
  # Model associations
  belongs_to :todo

  # Validations
  validates_presence_of :name
end
```

### Todo validations and associations app/models/todo.rb
```
class Todo < ApplicationRecord
  # Model association
  belongs_to :user
  has_many :items, dependent: :destroy

  # Validation
  validates_presence_of :title
end
``` 

### config/routes.rb
```
Rails.application.routes.draw do
  resources :todos do
    resources :items
  end
end
```

### Todo Controller app/controllers/todos_controller.rb
```
class TodosController < ApplicationController
  # GET /todos
  def index
    @todos = Todo.all
    render json: @todos, status: :ok
  end

  # GET /todos/:id
  def show
    @todo = Todo.find(params[:id])
    render json: @todo, status: :ok
  end

  # POST /todos
  def create
    @todo = Todo.create!(params.permit(:title, :user_id))
    render json: @todo, status: :created
  end

  # PUT /todos/:id
  def update
    @todo = Todo.find(params[:id])
    @todo.update(params.permit(:title, :user_id))
    head :no_content
  end

  # DELETE /todos/:id
  def destroy
    @todo = Todo.find(params[:id])
    @todo.destroy
    head :no_content
  end
end

```

### Exception handler app/controllers/concerns/exception_handler.rb
```
module ExceptionHandler
  extend ActiveSupport::Concern

  included do
    rescue_from ActiveRecord::RecordNotFound do |e|
      render json: { message: e.message }, status: :not_found
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      render json: { message: e.message }, status: :unprocessable_entity
    end
  end
end
```

### Include exception handler in app/controllers/application_controller.rb
```
class ApplicationController < ActionController::API
  include ExceptionHandler
end
```

### Item Controller app/controllers/items_controller.rb
```
class ItemsController < ApplicationController
  # GET /todos/:todo_id/items
  def index
    @todo = Todo.find(params[:todo_id])
    render json: @todo, status: :ok
  end

  # GET /todos/:todo_id/items/:id
  def show
    @todo = Todo.find(params[:todo_id])
    @item = @todo.items.find_by!(id: params[:id]) if @todo
    render json: @item, status: :ok
  end

  # POST /todos/:todo_id/items
  def create
    @todo = Todo.find(params[:todo_id])
    @todo.items.create!(params.permit(:name, :done))
    render json: @todo, status: :created
  end

  # PUT /todos/:todo_id/items/:id
  def update
    @todo = Todo.find(params[:todo_id])
    @item = @todo.items.find_by!(id: params[:id]) if @todo
    @item.update(params.permit(:name, :done))
    head :no_content
  end

  # DELETE /todos/:todo_id/items/:id
  def destroy
    @todo = Todo.find(params[:todo_id])
    @item = @todo.items.find_by!(id: params[:id]) if @todo
    @item.destroy
    head :no_content
  end
end
```

# Add JWT Authentication

### Add gems
```
gem 'bcrypt'
gem 'jwt'
```

### Create models
```
rails g model User name:string email:string password_digest:string
rails db:migrate
```

# User validations and associations app/models/user.rb
```
class User < ApplicationRecord
  # Encrypt password
  has_secure_password

  # Model associations
  has_many :todos, foreign_key: :user_id
  # Validations
  validates_presence_of :name, :email, :password_digest
end
```

### Create custom lib for JWT
```
mkdir app/lib
touch app/lib/json_web_token.rb
```

### app/lib/json_web_token.rb
```
class JsonWebToken
  # Secret to encode and decode token
  HMAC_SECRET = Rails.application.credentials.secret_key_base

  def self.encode(payload, exp = 24.hours.from_now)
    # Set expiry to 24 hours from creation time
    payload[:exp] = exp.to_i
    # Sign token with application secret
    JWT.encode(payload, HMAC_SECRET)
  end

  def self.decode(token)
    # Get payload; first index in decoded Array
    body = JWT.decode(token, HMAC_SECRET, true, { algorithm: 'HS256' }).first
    HashWithIndifferentAccess.new body
    # Rescue from all decode errors
  rescue JWT::DecodeError => e
    # Raise custom error to be handled by custom handler
    raise ExceptionHandler::InvalidToken, e.message
  end
end
```

### Update Exception handler app/controllers/concerns/exception_handler.rb
```
module ExceptionHandler
  extend ActiveSupport::Concern

  # Define custom error subclasses - rescue catches `StandardErrors`
  class AuthenticationError < StandardError; end
  class MissingToken < StandardError; end
  class InvalidToken < StandardError; end
  class ExpiredSignature < StandardError; end

  included do
    rescue_from ExceptionHandler::AuthenticationError do |e|
      render json: { message: e.message }, status: :unauthorized
    end

    rescue_from ExceptionHandler::MissingToken do |e|
      render json: { message: e.message }, status: :unauthorized
    end

    rescue_from ExceptionHandler::InvalidToken do |e|
      render json: { message: e.message }, status: :unauthorized
    end

    rescue_from ActiveRecord::RecordNotFound do |e|
      render json: { message: e.message }, status: :not_found
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      render json: { message: e.message }, status: :unprocessable_entity
    end
  end
end
```

### Authorize API reuests
```
mkdir app/auth
touch app/auth/authorize_api_request.rb
```

### app/auth/authorize_api_request.rb
```
class AuthorizeApiRequest
  def initialize(headers = {})
    @headers = headers
  end

  # Entry point - return valid user object
  def call
    {
      user: user
    }
  end

  private

  attr_reader :headers

  def user
    # Check if user is in the database
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    # Handle user not found
  rescue ActiveRecord::RecordNotFound => e
    raise(
      ExceptionHandler::InvalidToken,
      ("#{Message.invalid_token} #{e.message}")
    )
  end

  # Decode authentication token
  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
  end

  # Check for token in 'Authorization' headers
  def http_auth_header
    return headers['Authorization'].split(' ').last if headers['Authorization'].present?

    raise(ExceptionHandler::MissingToken, Message.missing_token)
  end
end

```

### Define custom messaging app/lib/message.rb
```
class Message
  def self.not_found(record = 'record')
    "Sorry, #{record} not found."
  end

  def self.invalid_credentials
    'Invalid credentials'
  end

  def self.invalid_token
    'Invalid token'
  end

  def self.missing_token
    'Missing token'
  end

  def self.unauthorized
    'Unauthorized request'
  end

  def self.account_created
    'Account created successfully'
  end

  def self.account_not_created
    'Account could not be created'
  end

  def self.expired_token
    'Sorry, your token has expired. Please login to continue.'
  end
end
```

### Authenticate User
```
touch app/auth/authenticate_user.rb
```

### app/auth/authenticate_user.rb
```
class AuthenticateUser
  def initialize(email, password)
    @email = email
    @password = password
  end

  # Entry point
  def call
    JsonWebToken.encode(user_id: user.id) if user
  end

  private

  attr_reader :email, :password

  # Verify user credentials
  def user
    user = User.find_by(email: email)
    return user if user&.authenticate(password)

    # Raise Authentication error if credentials are invalid
    raise(ExceptionHandler::AuthenticationError, Message.invalid_credentials)
  end
end

```

### Generate the Authentication controller
```
rails g controller Authentication
```

### app/controllers/authentication_controller.rb
```
class AuthenticationController < ApplicationController
  # Return token oce user is authenticated
  def authenticate
    auth_token = AuthenticateUser.new(auth_params[:email], auth_params[:password]).call
    response = { auth_token: auth_token, token_type: 'Bearer' }
    render json: response, status: :ok
  end

  def auth_params
    params.permit(:email, :password)
  end
end
```

### Add to config/routes.rb
```
Rails.application.routes.draw do
  # [...]
  post 'auth/login', to: 'authentication#authenticate'
end
```

### Generate users controller
```
rails g controller Users
```

### User controller app/controllers/users_controller.rb
```
class UsersController < ApplicationController
  # POST /signup
  # return authenticated token upon signup
  def create
    user = User.create!(params.permit(:name, :email, :password, :password_confirmation))
    auth_token = AuthenticateUser.new(user.email, user.password).call
    response = { message: Message.account_created, auth_token: auth_token, token_type: 'Bearer' }
    render json: response, status: :created
  end
end
```

### Add to config/routes.rb
```
Rails.application.routes.draw do
  # [...]
  post 'signup', to: 'users#create'
end
```

### Update todos controller app/controllers/todos_controller.rb
```
class TodosController < ApplicationController
  # [...]
  # GET /todos
  def index
    @todos = current_user.todos
    render json: @todos, status: :ok
  end
  # [...]
  # POST /todos
  def create
    @todo = current_user.todos.create!(params.permit(:title))
    render json: @todo, status: :created
  end
  # [...]
  private

  # remove `user_id` from list of permitted parameters
  params.permit(:title)
end
```

### Update app/controllers/application_controller.rb
```
class ApplicationController < ActionController::API
  include ExceptionHandler

  # Called before every action in controllers
  before_action :authorize_request
  attr_reader :current_user

  private

  # Check for valid request token and return user
  def authorize_request
    @current_user = (AuthorizeApiRequest.new(request.headers).call)[:user]
  end
end
```

### Update app/controllers/authentication_controller.rb
```
class AuthenticationController < ApplicationController
  skip_before_action :authorize_request, only: :authenticate
  # [...]
end
```

### Update app/controllers/users_controller.rb
```
class UsersController < ApplicationController
  skip_before_action :authorize_request, only: :create
  # [...]
end
```

### Update Todo model associations
```
class User < ApplicationRecord
  # [...]
  # Model associations
  has_many :todos, dependent: :destroy
end
```

### Update Todo controller
```
class TodosController < ApplicationController
  before_action :authenticate_user!

  # GET /todos
  def index
    @todos = current_user.todos
    render json: @todos, status: :ok
  end

  # [...]

  # POST /todos
  def create
    @todo = current_user.todos.create!(params.permit(:title))
    render json: @todo, status: :created
  end
end

```
### POSTMAN
```
http://127.0.0.1:3000/auth/signup POST {"name": "John Doe", "email": "user@example.com", "password": "password"}
http://127.0.0.1:3000/auth/login POST {"email": "user@example.com", "password": "password"}
```


# Add DEVISE JWT Authentication

### Add devise and devise-jwt gems
```
gem 'devise'
gem 'devise-jwt'
```

### Run devise install script
```
rails generate devise:install
rails generate devise user
```

### Add in  config/environments/development.rb and  config/environments/production.rb 
```
config.action_mailer.default_url_options = { host: '127.0.0.1', port: 3000 }
```

### Generate CreateJwtDenylist migration
```
rails generate migration CreateJwtDenylist
```

### Add to the CreateJwtDenylist migration
```
class CreateJwtDenylist < ActiveRecord::Migration[6.0]
  def change
    create_table :jwt_denylist do |t|
      t.string :jti, null: false
      t.datetime :expired_at, null: false
    end
    add_index :jwt_denylist, :jti
  end
end 
```

### Create app/models/jwt_denylist.rb
```
class JwtDenylist < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Denylist

  self.table_name = 'jwt_denylist'
end
```

### Add to the user model
```
class User < ApplicationRecord
  # [...] ,
  :timeoutable, :jwt_authenticatable, jwt_revocation_strategy: JwtDenylist
end
```

### Devise setup config/initializers/devise.rb
```
Devise.setup do |config|
  # [...]
  config.jwt do |jwt|
    jwt.secret = ENV['SECRET_KEY']
    warn('warning: jwt.secret can not be nil') if jwt.secret.nil?
    #  You need to tell which requests will dispatch tokens for the user that has been previously
    #  authenticated (usually through some other warden strategy, such as one requiring username and email parameters).
    #  To configure it, you can add the the request path to dispath_requests
    jwt.dispatch_requests = [['POST', %r{^users/sign_in$}]]

    #  You need to tell which requests will revoke incoming JWT tokens, and you can add the the request path to revocation_requests
    jwt.revocation_requests = [['DELETE', %r{^users/sign_out$}]]
    jwt.expiration_time = 1.day.to_i
  end
  config.remember_for = 1.day.to_i
  config.timeout_in = 1.day.to_i
  config.navigational_formats = []
end
```

### Update routes config/routes.rb
```
Rails.application.routes.draw do
  devise_for :users, controllers: { sessions: 'users/sessions', registrations: 'users/registrations' }
  resources :todos do
    resources :items
  end
end
```

### Optionally generate user controllers
```
rails generate devise:controllers users
```

### Update Todo model associations
```
class User < ApplicationRecord
  # [...]
  # Model associations
  has_many :todos, foreign_key: :user_id
end
```

### Update Todo controller
```
class TodosController < ApplicationController
  before_action :authenticate_user!

  # GET /todos
  def index
    @todos = current_user.todos
    render json: @todos, status: :ok
  end

  # [...]

  # POST /todos
  def create
    @todo = current_user.todos.create!(params.permit(:title))
    render json: @todo, status: :created
  end
end

```

### Update controllers/users/registrations_controller.rb
```
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json
end
```

### Update controllers/users/sessions_controller.rb
```
class Users::SessionsController < Devise::SessionsController
  respond_to :json

  private

  def respond_with(resource, _opts = {})
    render json: resource
  end

  def respond_to_on_destroy
    head :no_content
  end
end
```

### POSTMAN
```
http://127.0.0.1:3000/users POST {"user": {"email": "user@example.com", "password": "password"}}
http://127.0.0.1:3000/users/sign_in POST {"user": {"email": "user@example.com", "password": "password"}}
http://127.0.0.1:3000/users/sign_out DELETE
```

# RSpec unit tests

### Add gems
```
gem 'rspec-rails', '~> 4.0.1'
gem 'database_cleaner', '~> 1.8.5'
gem 'factory_bot_rails', '~> 6.1.0'
gem 'faker', '~> 2.15.1'
gem 'shoulda-matchers', '~> 4.4.1'
```

### Run RSpec install
```
rails generate rspec:install
```

### RSpec configuration spec/rails_helper.rb
```
# Require database cleaner 
require 'database_cleaner'

# [...]
# configure shoulda matchers to use rspec
Shoulda::Matchers.configure do |config|
  config.integrate do |with|
    with.test_framework :rspec
    with.library :rails
  end
end

# [...]
RSpec.configure do |config|
  # [...]
  # add `FactoryBot` methods
  config.include FactoryBot::Syntax::Methods

  # start by truncating all the tables
  config.before(:suite) do
    DatabaseCleaner.clean_with(:truncation)
    DatabaseCleaner.strategy = :transaction
  end

  # start the transaction strategy as examples are run
  config.around(:each) do |example|
    DatabaseCleaner.cleaning do
      example.run
    end
  end
  # [...]
  config.default_formatter = 'doc'
end
```

## RSpec model tests

### Add Todo model test spec/models/todo_spec.rb
```
require 'rails_helper'

# Test suite for the Todo model
RSpec.describe Todo, type: :model do
  # Association test
  # ensure Todo model has a one to many relationship with the Item model
  it { should belong_to(:user) }
  it { should have_many(:items).dependent(:destroy) }

  # Validation tests
  # ensure columns title and created_by are present before saving
  it { should validate_presence_of(:title) }
end
```

### Add Item model test spec/models/item_spec.rb
```
require 'rails_helper'

# Test suite for the Item model
RSpec.describe Item, type: :model do
  # Association test
  # ensure an item record belongs to a single todo record
  it { should belong_to(:todo) }

  # Validation test
  # ensure name is present before saving
  it { should validate_presence_of(:name) }
end
```

### Add User model test spec/models/user_spec.rb
```
require 'rails_helper'

# Test suite for user model
RSpec.describe User, type: :model do
  # Association test
  it { should have_many(:todos) }

  # Validation test
  # ensure email and password are present
  it { should validate_presence_of(:email) }
  it { should validate_presence_of(:password) }
end
```

## RSpec controllers tests

### Create factory files
```
touch spec/factories/todos.rb
touch spec/factories/items.rb
touch spec/factories/users.rb
```

### Define spec/factories/todos.rb
```
FactoryBot.define do
  factory :todo do
    title { Faker::Lorem.word }
    user
  end
end
```

### Define spec/factories/items.rb
```
FactoryBot.define do
  factory :item do
    name { Faker::Movies::Lebowski.character }
    done { false }
    todo
  end
end
```

### Define spec/factories/users.rb
```
FactoryBot.define do
  factory :user do
    sequence(:email, 10) { |n| "test-#{n}@example.com" }
    password { 'Password123' }
  end
end
```

### Todo spec/controllers/todos_spec.rb
```
require 'rails_helper'
require_relative '../support/devise'

RSpec.describe TodosController, type: :controller do
  # initialize test data
  let!(:user) { create(:user) }
  let!(:todos) { create_list(:todo, 5, user_id: user.id) }
  let(:todo_id) { todos.first.id }

  # Test suite for GET /todos
  describe 'GET /todos' do
    login_user

    it 'returns todos' do
      response = get :index
      expect(JSON.parse(response.body)).not_to be_empty
      expect(JSON.parse(response.body).size).to eq(5)
    end

    it 'returns status code 200' do
      response = get :index
      expect(response).to have_http_status(200)
    end
  end

  # Test suite for GET /todos/:id
  describe 'GET /todos/:id' do
    login_user

    context 'when the record exists' do
      it 'returns the todo' do
        response = get :show, params: { id: todo_id }
        expect(JSON.parse(response.body)).not_to be_empty
        expect(JSON.parse(response.body)['id']).to eq(todo_id)
      end

      it 'returns status code 200' do
        response = get :show, params: { id: todo_id }
        expect(response).to have_http_status(200)
      end
    end

    context 'when the record does not exist' do
      let(:todo_id) { 100 }

      it 'returns status code 404' do
        response = get :show, params: { id: todo_id }
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        response = get :show, params: { id: todo_id }
        expect(response.body).to match(/Couldn't find Todo/)
      end
    end
  end

  # Test suite for POST /todos
  describe 'POST /todos' do
    login_user

    context 'when the request is valid' do
      it 'creates a todo' do

        response = post :create, params: { title: 'Learn Elixir' }
        expect(JSON.parse(response.body)['title']).to eq('Learn Elixir')
      end

      it 'returns status code 201' do
        response = post :create, params: { title: 'Learn Elixir' }
        expect(response).to have_http_status(201)
      end
    end

    context 'when the request is invalid' do
      it 'returns status code 422' do
        response = post :create, params: {}
        expect(response).to have_http_status(422)
      end

      it 'returns a validation failure message' do
        response = post :create, params: {}
        expect(response.body).to match(/Validation failed: Title can't be blank/)
      end
    end
  end

  # Test suite for PUT /todos/:id
  describe 'PUT /todos/:id' do
    login_user

    context 'when the record exists' do
      it 'updates the record' do
        response = put :update, params: { id: todo_id, title: 'Shopping' }
        expect(response.body).to be_empty
      end

      it 'returns status code 204' do
        response = put :update, params: { id: todo_id, title: 'Shopping' }
        expect(response).to have_http_status(204)
      end
    end
  end

  # Test suite for DELETE /todos/:id
  describe 'DELETE /todos/:id' do
    login_user

    it 'returns status code 204' do
      response = delete :destroy, params: { id: todo_id }
      expect(response).to have_http_status(204)
    end
  end
end
```

### Controller macros spec/support/controller_macros.rb
```
module ControllerMacros
  def login_user
    before(:each) do
      @request.env['devise.mapping'] = Devise.mappings[:user]
      user = FactoryBot.create(:user)
      create_list(:todo, 5, user_id: user.id)
      sign_in user
    end
  end
end

```

### JSON helper spec/support/devise.rb
```
require_relative './controller_macros'

RSpec.configure do |config|
  # For Devise > 4.1.1
  config.include Devise::Test::ControllerHelpers, type: :controller
  # Use the following instead if you are on Devise <= 4.1.1
  # config.include Devise::TestHelpers, :type => :controller
  config.extend ControllerMacros, type: :controller
end
```

### Autoload spec/support directory spec/rails_helper.rb 
```
require_relative 'support/controller_macros'
require 'devise'
Dir[Rails.root.join('spec/support/**/*.rb')].sort.each { |f| require f }
# [...]
RSpec.configuration do |config|
  # [...]
  config.include RequestSpecHelper, type: :request
  # [...]
  config.include Devise::Test::ControllerHelpers, type: :controller
  config.include Devise::Test::IntegrationHelpers, type: :request
  config.extend ControllerMacros, type: :controller
end
```

### todos/items controller spec/controllers/items_spec.rb
```
require 'rails_helper'
require_relative '../support/devise'

RSpec.describe ItemsController, type: :controller do
  # Initialize the test data
  let!(:todo) { create(:todo) }
  let!(:items) { create_list(:item, 5, todo_id: todo.id) }
  let(:todo_id) { todo.id }
  let(:id) { items.first.id }

  # Test suite for GET /todos/:todo_id/items
  describe 'GET /todos/:todo_id/items' do
    login_user

    context 'when todo exists' do
      it 'returns status code 200' do
        response = get :index, params: { todo_id: todo_id }
        expect(response).to have_http_status(200)
      end

      it 'returns all todo items' do
        response = get :index, params: { todo_id: todo_id }
        expect(JSON.parse(response.body).size).to eq(5)
      end
    end

    context 'when todo does not exist' do
      let(:todo_id) { 0 }

      it 'returns status code 404' do
        response = get :index, params: { todo_id: todo_id }
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        response = get :index, params: { todo_id: todo_id }
        expect(response.body).to match(/Couldn't find Todo/)
      end
    end
  end

  # Test suite for GET /todos/:todo_id/items/:id
  describe 'GET /todos/:todo_id/items/:id' do
    login_user

    context 'when todo item exists' do
      it 'returns status code 200' do
        response = get :show, params: { todo_id: todo_id, id: id }
        expect(response).to have_http_status(200)
      end

      it 'returns the item' do
        response = get :show, params: { todo_id: todo_id, id: id }
        expect(JSON.parse(response.body)['id']).to eq(id)
      end
    end

    context 'when todo item does not exist' do
      let(:id) { 0 }

      it 'returns status code 404' do
        response = get :show, params: { todo_id: todo_id, id: id }
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        response = get :show, params: { todo_id: todo_id, id: id }
        expect(response.body).to match(/Couldn't find Item/)
      end
    end
  end

  # Test suite for PUT /todos/:todo_id/items
  describe 'POST /todos/:todo_id/items' do
    login_user

    context 'when request attributes are valid' do
      it 'returns status code 201' do
        response = post :create, params: { todo_id: todo_id, name: 'Visit Narnia', done: false }
        expect(response).to have_http_status(201)
      end
    end

    context 'when an invalid request' do
      it 'returns status code 422' do
        response = post :create, params: { todo_id: todo_id }
        expect(response).to have_http_status(422)
      end

      it 'returns a failure message' do
        response = post :create, params: { todo_id: todo_id }
        expect(response.body).to match(/Validation failed: Name can't be blank/)
      end
    end
  end

  # Test suite for PUT /todos/:todo_id/items/:id
  describe 'PUT /todos/:todo_id/items/:id' do
    login_user

    context 'when item exists' do
      it 'returns status code 204' do
        response = put :update, params: { todo_id: todo_id, id: id, name: 'Mozart' }
        expect(response).to have_http_status(204)
      end
    end

    context 'when the item does not exist' do
      let(:id) { 0 }

      it 'returns status code 404' do
        response = put :update, params: { todo_id: todo_id, id: id, name: 'Mozart' }
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        response = put :update, params: { todo_id: todo_id, id: id, name: 'Mozart' }
        expect(response.body).to match(/Couldn't find Item/)
      end
    end
  end

  # Test suite for DELETE /todos/:id
  describe 'DELETE /todos/:id' do
    login_user

    it 'returns status code 204' do
      response = delete :destroy, params: { todo_id: todo_id, id: id }
      expect(response).to have_http_status(204)
    end
  end
end
```
