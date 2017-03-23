defmodule AuthedApp.API.V1.SessionControllerTest do
  use AuthedApp.ConnCase
  import AuthedApp.Test.Factory

  @valid_attrs %{email: "user@mail.com", password: "password"}
  @invalid_attr %{email: "foo"}

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
    conn = post conn, api_v1_session_path(conn, :signup), @invalid_attr
    {:ok, expected} =
      %{errors: [%{password: "can't be blank"}, %{email: "has invalid format"}]}
    |> Poison.encode
    assert json_response(conn, 400)
    assert conn.resp_body == expected
    assert get_resp_header(conn, "authorization") == []
  end

  test "POST /signup with valid parameters", %{anon_conn: conn} do
    conn = post conn, api_v1_session_path(conn, :signup), @valid_attrs
    assert json_response(conn, 201) == %{}
    assert get_resp_header(conn, "authorization") != []
  end

  test "PUT /login with invalid parameters", %{anon_conn: conn} do
    conn = put conn, api_v1_session_path(conn, :login), @invalid_attr
    {:ok, expected} =
      %{errors: [%{email: "has invalid format"}, %{password: "can't be blank"}]}
    |> Poison.encode
    assert json_response(conn, 400)
    assert conn.resp_body == expected
    assert get_resp_header(conn, "authorization") == []
  end

  test "PUT /login with wrong email", %{anon_conn: conn, user: user} do
    conn = put conn, api_v1_session_path(conn, :login),
      %{email: "foo" <> user.email, password: user.password}
    assert json_response(conn, 403) == %{}
    assert get_resp_header(conn, "authorization") == []
  end

  test "PUT /login with wrong password", %{anon_conn: conn, user: user} do

      conn = put conn, api_v1_session_path(conn, :login),
      %{email: user.email, password: "foo" <> user.password}
    assert json_response(conn, 403) == %{}
    assert get_resp_header(conn, "authorization") == []
  end

  test "PUT /login with valid parameters", %{anon_conn: conn, user: user} do
    conn = put conn, api_v1_session_path(conn, :login),
      %{email: user.email, password: user.password}
    assert json_response(conn, 200) == %{}
    assert get_resp_header(conn, "authorization") != []
  end
end
