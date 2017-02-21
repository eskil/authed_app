defmodule AuthedApp.SessionController do
  use AuthedApp.Web, :controller

  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]

  alias AuthedApp.User

  plug :scrub_params, "session" when action in [:create]

  def new(conn, _params) do
    render(conn, "new.html")
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    # Get user by email
    user = Repo.get_by(User, email: email)

    result = cond do
      # We have a user and the hashed password matches the db one.
      user && checkpw(password, user.password_hash) ->
        {:ok, login(conn, user)}
      # We have a user but the password check failed.
      user ->
        {:error, :unauthorized, conn}
      # Didn't find the email, call dummy_checkpw to fake delay.
      true ->
        dummy_checkpw()
        {:error, :not_found, conn}
    end

    case result do
      {:ok, conn} ->
        conn
        |> put_flash(:info, "You're logged in")
        |> redirect(to: page_path(conn, :index))
      {:error, _reason, conn} ->
        conn
        |> put_flash(:error, "Invalid email or password")
        |> render("new.html")
    end
  end

  defp login(conn, user) do
    conn
    |> Guardian.Plug.sign_in(user)
  end

  def delete(conn, _params) do
    conn
    |> logout
    |> put_flash(:info, "Logged out")
    |> redirect(to: page_path(conn, :index))
  end

  defp logout(conn) do
    Guardian.Plug.sign_out(conn)
  end
end
