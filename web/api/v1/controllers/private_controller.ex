defmodule AuthedApp.API.V1.PrivateController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
