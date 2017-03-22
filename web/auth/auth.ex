defmodule AuthedApp.Auth do
  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]
  import  Plug.Conn

  alias AuthedApp.Repo
  alias AuthedApp.User

  def login(conn, user, :html) do
    conn
    |> Guardian.Plug.sign_in(user)
  end

  def login(conn, user, :json) do
    conn = Guardian.Plug.api_sign_in(conn, user)
    with jwt = Guardian.Plug.current_token(conn),
         {:ok, claims} = Guardian.Plug.claims(conn),
           exp = Map.get(claims, "exp")
      do
      conn
      |> put_resp_header("authorization", "#{jwt}")
      |> put_resp_header("x-expires", "#{exp}")
    end
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
        {:ok, login(conn, user, response_type(conn))}
      # We have a user but the password check failed.
      user ->
        {:error, :unauthorized, conn}
      # Didn't find the email, call dummy_checkpw to fake delay.
      true ->
        dummy_checkpw()
        {:error, :not_found, conn}
    end
  end

  defp response_type(conn) do
    accept = accept_header(conn)
    if Regex.match?(~r/json/, accept) do
      :json
    else
      :html
    end
  end

  defp accept_header(conn)  do
    value = conn
      |> get_req_header("accept")
      |> List.first

    value || ""
  end
end
