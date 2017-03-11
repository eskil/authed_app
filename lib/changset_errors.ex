defmodule AuthedApp.ChangesetErrors do
  def changeset_errors_as_dict(changeset) do
    for {key, {message, _values}} <- changeset.errors, do:
        %{key => message}
  end

  def changeset_errors(changeset) do
     changeset.errors
     |> Enum.map(fn {k, v} -> "Parameter #{k} #{render_detail(v)}" end)
  end

  defp render_detail({message, values}) do
    Enum.reduce values, message, fn {k, v}, acc ->
      String.replace(acc, "%{#{k}}", to_string(v))
    end
  end

  defp render_detail(message) do
    message
  end
end
