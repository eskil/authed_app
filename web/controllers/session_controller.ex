defmodule AuthedApp.SessionController do
  use AuthedApp.Web, :controller

  plug :scrub_params, "session" when action in [:create]

  def new(conn, _params) do
    render(conn, "new.html")
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    # tbd
  end

  def delete(conn, _params) do
    # tbd
  end
end
