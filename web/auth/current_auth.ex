defmodule AuthedApp.CurrentUser do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    assign(conn, :current_user, Guardian.Plug.current_resource(conn))
  end
end
