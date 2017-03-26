defmodule AuthedApp.API.V1.SessionView do
  use AuthedApp.Web, :view

  def render("error.json", %{errors: errors}) do
    %{errors: errors}
  end

  def render("login.json", _) do
    %{}
  end
end
