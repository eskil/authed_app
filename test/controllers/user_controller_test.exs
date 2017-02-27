defmodule AuthedApp.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    anon_conn = build_conn()
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
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
                %{"user" => %{}})
    IO.inspect conn, pretty: true
    assert redirected_to(conn) == page_path(conn, :index)
  end
end
