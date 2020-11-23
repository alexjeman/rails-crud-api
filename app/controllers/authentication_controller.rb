class AuthenticationController < ApplicationController
  skip_before_action :authorize_request, only: :authenticate

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
