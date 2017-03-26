defmodule AuthedApp.API.V1.PrivateView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{private_news: news}
  end
end
