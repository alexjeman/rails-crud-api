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
