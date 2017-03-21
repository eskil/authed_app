defmodule AuthedApp.Changesets do
  def errors_to_dict(changeset) do
    changeset.errors
    |> Enum.map(fn {k, v} -> %{k => reduce_message(v)} end)
  end

  defp reduce_message({message, _values}) do
    message
  end

  defp reduce_message(message) do
    message
  end
end
