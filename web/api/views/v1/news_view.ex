defmodule AuthedApp.API.V1.NewsView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{news_today: news}
  end
end
