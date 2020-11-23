class TodosController < ApplicationController
  # GET /todos
  def index
    @todos = current_user.todos
    render json: @todos, status: :ok
  end

  # GET /todos/:id
  def show
    @todo = Todo.find(params[:id])
    render json: @todo, status: :ok
  end

  # POST /todos
  def create
    @todo = current_user.todos.create!(params.permit(:title))
    render json: @todo, status: :created
  end

  # PUT /todos/:id
  def update
    @todo = Todo.find(params[:id])
    @todo.update(params.permit(:title))
    head :no_content
  end

  # DELETE /todos/:id
  def destroy
    @todo = Todo.find(params[:id])
    @todo.destroy
    head :no_content
  end
end
