defmodule AuthedApp.API.V1.Admin.UserView do
  use AuthedApp.Web, :view

  alias AuthedApp.User

  def render("index.json", %{users: users}) do
    %{users: Enum.map(users, &User.to_json/1)}
  end
end
