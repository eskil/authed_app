defmodule AuthedApp.GuardianErrorHandler do
  import AuthedApp.Router.Helpers

  def unauthenticated(conn, _params) do
    conn
    |> Phoenix.Controller.put_flash(:error, "You must be signed in to access this page.")
    |> Phoenix.Controller.redirect(to: session_path(conn, :new))
  end
end
