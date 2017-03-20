defmodule AuthedApp.PublicControllerTest do
  use AuthedApp.ConnCase

  test "GET /public", %{conn: conn} do
    conn = get conn, public_path(conn, :index)
    assert html_response(conn, 200) =~ "news today"
  end
end
