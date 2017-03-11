defmodule AuthedApp.API.V1.SessionView do
  use AuthedApp.Web, :view

  def render("login.json", %{status: :ok}) do
    %{status: :ok}
  end

  def render("login.json", %{status: :error, messages: messages, errors: errors}) do
    %{status: :error, messages: messages, errors: errors}
  end

  def render("login.json", %{status: :failed}) do
    %{status: :failed}
  end
end
