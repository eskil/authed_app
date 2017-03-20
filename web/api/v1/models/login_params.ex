defmodule AuthedApp.API.V1.LoginParams do
  use AuthedApp.Web, :model

  schema "LoginParams" do
    field :email, :string
    field :password, :string
  end

  @required_fields [:email, :password]
  @optional_fields []

  def changeset(model, params \\ :empty) do
    model
    |> cast(params, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end
end
