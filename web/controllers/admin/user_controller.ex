defmodule AuthedApp.Admin.UserController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  def index(conn, _params) do
    render(conn, "index.html", users: Repo.all(User))
  end
end
