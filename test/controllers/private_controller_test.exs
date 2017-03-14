defmodule AuthedApp.PrivateControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    # Get a connection, see https://hexdocs.pm/phoenix/Phoenix.ConnTest.html#build_conn/0.
    anon_conn = build_conn()
    # Use AuthedApp.Test.Factory to insert the user created by user_factory/0.
    user = insert(:user)
    # Sign in this user and get the signed in connection.
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    # Return ok plus a map of values test functions can match against.
    {:ok, %{
        user: user,
        anon_conn: anon_conn,
        user_conn: user_conn
        }
    }
  end

  # Note this test uses anon_conn to test unregistered users.
  test "GET /private as anonymous redirects to registration", %{anon_conn: conn} do
    conn = get conn, private_path(conn, :index)
    assert redirected_to(conn) == session_path(conn, :new)
  end

  # Note this test uses user_conn to test registered and signed in users.
  test "GET /private as user ", %{user_conn: conn} do
    conn = get conn, private_path(conn, :index)
    assert html_response(conn, 200) =~ "info today"
  end
end
