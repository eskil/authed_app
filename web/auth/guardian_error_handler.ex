defmodule AuthedApp.GuardianErrorHandler do
  import AuthedApp.Router.Helpers
  import Phoenix.Controller

  def unauthenticated(conn, _params) do
    conn
    |> put_flash(:error, "You must be signed in to access this page.")
    |> redirect(to: session_path(conn, :new))
  end
end
