class UsersController < ApplicationController
  skip_before_action :authorize_request, only: :create

  # POST /signup
  # return authenticated token upon signup
  def create
    user = User.create!(params.permit(:name, :email, :password, :password_confirmation))
    auth_token = AuthenticateUser.new(user.email, user.password).call
    response = { message: Message.account_created, auth_token: auth_token, token_type: 'Bearer' }
    render json: response, status: :created
  end
end
