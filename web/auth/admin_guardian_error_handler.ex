defmodule AuthedApp.Admin.GuardianErrorHandler do
  import Phoenix.Controller
  import Plug.Conn

  def unauthenticated(conn, _params) do
    conn
    |> put_status(:not_found)
    |> render(AuthedApp.ErrorView, "404.html")
    |> halt
  end
end
