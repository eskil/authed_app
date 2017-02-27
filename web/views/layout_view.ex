defmodule AuthedApp.LayoutView do
  use AuthedApp.Web, :view

  def navigation_header(assigns) do
    render("navigation_header.html", assigns)
  end

  def footer(assigns) do
    render("footer.html", assigns)
  end
end
