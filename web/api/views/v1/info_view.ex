defmodule AuthedApp.API.V1.InfoView do
  use AuthedApp.Web, :view

  def render("index.json", %{info: info}) do
    %{info_today: info}
  end
end
