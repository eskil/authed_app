defmodule AuthedApp.PublicController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end