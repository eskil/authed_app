defmodule AuthedApp.SessionControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    user = insert(:user)
    anon_conn = build_conn()
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
        anon_conn: anon_conn
        }
    }
  end

  test "GET /sessions/new", %{conn: conn} do
    conn = get(conn, session_path(conn, :new))
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "POST /sessions/new with invalid email", %{anon_conn: conn, user: user} do
    conn = post(conn, session_path(conn, :create),
                %{"session" => %{
                   "email" => "typo" <> user.email,
                   "password" => user.password
                 }})
    assert html_response(conn, 200) =~ "Invalid email or password"
  end

  test "POST /sessions/new with invalid password", %{anon_conn: conn, user: user} do
    conn = post(conn, session_path(conn, :create),
                %{"session" => %{
                   "email" => user.email,
                   "password" => "typo" <> user.password
                 }})
    assert html_response(conn, 200) =~ "Invalid email or password"
  end

  test "POST /sessions/new with valid parameters", %{anon_conn: conn, user: user} do
    conn = post(conn, session_path(conn, :create),
                %{"session" => %{
                   "email" => user.email,
                   "password" => user.password
                 }})
    assert redirected_to(conn) == page_path(conn, :index)
    assert get_flash(conn) == %{"info" => "You're signed in"}
  end

  test "DELETE /sessions/:id", %{conn: conn, user: user} do
    conn = delete(conn, session_path(conn, :delete, user.id))
    assert redirected_to(conn) == page_path(conn, :index)
  end
end
