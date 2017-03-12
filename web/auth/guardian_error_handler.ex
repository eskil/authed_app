defmodule AuthedApp.GuardianErrorHandler do
  use AuthedApp.Web, :controller
  import AuthedApp.Router.Helpers
  #import Phoenix.Controller

  def handle_unauthenticated(conn, "json") do
    conn
    |> put_status(:forbidden)
    |> json(%{})
  end

  def handle_unauthenticated(conn, "html") do
    conn
    |> put_flash(:error, "You must be signed in to access this page.")
    |> redirect(to: session_path(conn, :new))
  end

  def unauthenticated(conn, _params) do
    handle_unauthenticated(conn, get_format(conn))
  end
end
