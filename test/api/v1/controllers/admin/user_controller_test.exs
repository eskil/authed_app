defmodule AuthedApp.API.V1.Admin.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    anon_conn = build_conn()
    |> put_req_header("accept", "application/json")
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

  test "GET /admin/users as anonymous", %{anon_conn: conn} do
    conn = get conn, api_v1_admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as user", %{user_conn: conn} do
    conn = get conn, api_v1_admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as admin", %{admin_conn: conn, user: user, admin: admin} do
    conn = get conn, api_v1_admin_user_path(conn, :index)
    {:ok, expected} =
      %{users: [
           %{name: user.name, email: user.email, is_admin: false, id: user.id},
           %{name: admin.name, email: admin.email, is_admin: false, id: admin.id}
         ]}
    |> Poison.encode

    assert json_response(conn, 200)
    assert conn.resp_body == expected
  end
end
