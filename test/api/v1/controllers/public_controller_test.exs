defmodule AuthedApp.API.V1.PublicControllerTest do
  use AuthedApp.ConnCase

  test "GET /public", %{conn: conn} do
    conn = get conn, api_v1_public_path(conn, :index)
    assert json_response(conn, 200) == %{"public_news" => "none"}
  end
end
