defmodule AuthedApp.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  alias AuthedApp.User

  setup do
    anon_conn = build_conn()
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
        anon_conn: anon_conn
        }
    }
  end

  test "GET /users/new", %{conn: conn} do
    conn = get(conn, user_path(conn, :new))
    assert html_response(conn, 200) =~ "User Registration"
  end

  test "POST /users fails when missing parameters", %{conn: conn} do
    conn = post(conn, user_path(conn, :create),
                %{"user" => %{}})
    assert html_response(conn, 200) =~ "There are some errors"
  end

  test "POST /users", %{conn: conn} do
    conn = post(conn, user_path(conn, :create),
                %{"user" =>
                   %{
                     "email" => "user@email.com",
                     "password" => "password",
                     "name" => "User Name"
                   }
                 })
    user = Repo.get_by(User, email: "user@email.com")
    # Check a id was assigned, a hashed password.
    assert user.id && user.password_hash && !user.password
    assert redirected_to(conn) == user_path(conn, :show, user.id)
  end

  test "GET /users/:id as anonymous", %{anon_conn: conn, user: user} do
    conn = get(conn, user_path(conn, :show, user.id))
    assert html_response(conn, 200) =~ user.name
  end
end
