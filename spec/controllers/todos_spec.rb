require 'rails_helper'
require_relative '../support/devise'

RSpec.describe TodosController, type: :controller do
  # initialize test data
  let(:user) { create(:user) }
  let!(:todos) { create_list(:todo, 10, created_by: 1) }
  let(:todo_id) { todos.first.id }

  # Test suite for GET /todos
  describe 'GET /todos' do
    login_user

    it 'returns todos' do
      response = get :index
      expect(JSON.parse(response.body)).not_to be_empty
      expect(JSON.parse(response.body).size).to eq(10)
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
