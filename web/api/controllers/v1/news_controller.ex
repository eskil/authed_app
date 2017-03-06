defmodule AuthedApp.API.V1.NewsController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
