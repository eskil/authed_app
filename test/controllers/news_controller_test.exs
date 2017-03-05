defmodule AuthedApp.NewsControllerTest do
  use AuthedApp.ConnCase

  test "GET /news", %{conn: conn} do
    conn = get conn, news_path(conn, :index)
    assert html_response(conn, 200) =~ "news today"
  end
end
