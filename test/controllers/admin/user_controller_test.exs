defmodule AuthedApp.Admin.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    anon_conn = build_conn()
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    admin = insert(:user) |> make_admin
    admin_conn = Guardian.Plug.api_sign_in(anon_conn, admin, :token)
    {:ok, %{
        user: user,
        admin: admin,
        anon_conn: anon_conn,
        user_conn: user_conn,
        admin_conn: admin_conn
        }
    }
  end

  test "GET /admin/users as unregistered redirects to registration", %{anon_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as user redirects to registration", %{user_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as admin", %{admin_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert html_response(conn, 200) =~ "Users"
  end
end
