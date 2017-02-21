defmodule AuthedApp.SessionController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  plug :scrub_params, "session" when action in [:create]

  def new(conn, _params) do
    render(conn, "new.html")
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    case AuthedApp.Auth.login_by_email_and_password(email, password) do
      {:ok, conn} ->
        conn
        |> put_flash(:info, "You're signed in")
        |> redirect(to: page_path(conn, :index))
      {:error, _reason, conn} ->
        conn
        |> put_flash(:error, "Invalid email or password")
        |> render("new.html")
    end
  end

  def delete(conn, _params) do
    conn
    |> AuthedApp.Auth.logout
    |> put_flash(:info, "Logged out")
    |> redirect(to: page_path(conn, :index))
  end
end
