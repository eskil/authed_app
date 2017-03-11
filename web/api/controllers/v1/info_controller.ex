defmodule AuthedApp.API.V1.InfoController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", info: "none")
  end
end
