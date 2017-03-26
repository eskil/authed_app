defmodule AuthedApp.API.V1.Admin.UserController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  def index(conn, params) do
    conn
    |> render("index.json", users: Repo.all(User))
  end
end
