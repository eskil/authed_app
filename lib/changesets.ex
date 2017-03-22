defmodule AuthedApp.Changesets do
  def errors_to_dict(changeset) do
    changeset.errors
    |> Enum.map(fn {k, v} -> %{k => render_message(v)} end)
  end

  defp render_message({message, values}) do
    values
    |> Enum.reduce(message, fn {k, v}, acc ->
      String.replace(acc, "%{#{k}}", to_string(v))
    end)
  end

  defp render_message(message) do
    message
  end
end
