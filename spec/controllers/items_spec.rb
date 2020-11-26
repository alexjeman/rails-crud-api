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
