defmodule AuthedApp.Auth do
  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]

  alias AuthedApp.Repo
  alias AuthedApp.User

  def login(conn, user) do
    conn
    |> Guardian.Plug.sign_in(user)
  end

  def logout(conn) do
    Guardian.Plug.sign_out(conn)
  end

  def login_by_email_and_password(conn, email, password) do
    # Get user by email
    user = Repo.get_by(User, email: email)

    cond do
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
  end
end
