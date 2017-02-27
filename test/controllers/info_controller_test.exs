defmodule AuthedApp.InfoControllerTest do
  use AuthedApp.ConnCase

  test "unregistered GET /info redirects to registration", %{conn: conn} do
    conn = get conn, info_path(conn, :index)
    assert redirected_to(conn) == session_path(conn, :new)
  end
end
