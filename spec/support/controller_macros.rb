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
