defmodule AuthedApp.API.V1.PublicView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{public_news: news}
  end
end
