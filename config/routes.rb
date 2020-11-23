Rails.application.routes.draw do
  resources :todos do
    resources :items
  end
  post 'auth/login', to: 'authentication#authenticate'
  post 'auth/signup', to: 'users#create'
end
