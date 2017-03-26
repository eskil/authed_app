defmodule AuthedApp.API.Admin.GuardianErrorHandler do
  import Phoenix.Controller
  import Plug.Conn

  def unauthenticated(conn, _params) do
    conn
    |> put_status(:not_found)
    |> json(%{})
    |> halt
  end
end
