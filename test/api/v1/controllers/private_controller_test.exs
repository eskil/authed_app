defmodule AuthedApp.API.V1.PrivateControllerTest do
  use AuthedApp.ConnCase
  import AuthedApp.Test.Factory

  setup do
    user = insert(:user)
    anon_conn = build_conn()
    |> put_req_header("accept", "application/json")
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        anon_conn: anon_conn,
        user_conn: user_conn
        }
    }
  end

  test "GET /public as anonymous", %{anon_conn: conn} do
    conn = get conn, api_v1_private_path(conn, :index)
    assert json_response(conn, 401) == %{"errors" => ["Unauthenticated"]}
  end

  test "GET /public as user", %{user_conn: conn} do
    conn = get conn, api_v1_private_path(conn, :index)
    assert json_response(conn, 200) == %{"private_news" => "none"}
  end
end
