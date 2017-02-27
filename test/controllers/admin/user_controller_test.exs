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

  test "unregistered GET /admin/users redirects to registration", %{anon_conn: conn} do
    response = get conn, admin_user_path(conn, :index)
    assert response.status == 404
  end

  test "user GET /admin/users redirects to registration", %{user_conn: conn} do
    response = get conn, admin_user_path(conn, :index)
    assert response.status == 404
  end

  test "admin GET /admin/users", %{admin_conn: conn} do
    response = get conn, admin_user_path(conn, :index)
    assert html_response(response, 200) =~ "Users"
  end
end
