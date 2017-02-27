defmodule AuthedApp.SessionControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(build_conn(), user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
        }
    }
  end

  test "GET /sessions/new", %{conn: conn} do
    conn = get(conn, session_path(conn, :new))
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "POST /sessions/new", %{conn: conn} do
    conn = post(conn, session_path(conn, :create),
                %{"session" => %{"email" => "foo", "password" => "bar"}})
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "DELETE /sessions/:id", %{conn: conn, user: user} do
    conn = delete(conn, session_path(conn, :delete, user.id))
    assert redirected_to(conn) == page_path(conn, :index)
  end
end
