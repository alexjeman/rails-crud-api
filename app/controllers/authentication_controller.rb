class AuthenticationController < ApplicationController
  # Return token oce user is authenticated
  def authenticate
    auth_token = AuthenticateUser.new(auth_params[:email], auth_params[:password]).call
    render json: auth_token, status: :ok
  end

  def auth_params
    params.permit(:email, :password)
  end
end
