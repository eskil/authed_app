defmodule AuthedApp.SchemaToJson do
  defmacro __using__(opts) do
    quote do
      def to_json(obj) do
        for key <- unquote(opts[:json_fields]), into: %{}, do: {key, Map.fetch!(obj, key)}
      end
    end
  end
end
