class ApplicationController < ActionController::API
  include ExceptionHandler

  # Called before every action in controllers
  before_action :authenticate_user!
end
