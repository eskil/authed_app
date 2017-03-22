defmodule AuthedApp.API.V1.SessionControllerTest do
  use AuthedApp.ConnCase
  import AuthedApp.Test.Factory

  @valid_attrs %{email: "user@mail.com", password: "password"}
  @invalid_attrs %{email: "foo"}

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

  test "POST /signup with invalid parameters", %{anon_conn: conn} do
    conn = post conn, api_v1_session_path(conn, :signup), @invalid_attrs
    assert json_response(conn, 400) == Poison.decode!('
    {"errors":
      [
        {"password": "can\'t be blank"},
        {"email": "has invalid format"}
      ]
    }')
    assert get_resp_header(conn, "authorization") == []
  end

  test "POST /signup with valid parameters", %{anon_conn: conn} do
    conn = post conn, api_v1_session_path(conn, :signup), @valid_attrs
    assert json_response(conn, 201) == %{}
    assert get_resp_header(conn, "authorization") != []
  end
end
