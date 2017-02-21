defmodule AuthedApp.User do
  use AuthedApp.Web, :model

  schema "users" do
    field :email, :string
    field :name, :string
    field :password, :string, virtual: true
    field :password_hash, :string
    field :is_admin, :boolean, default: false

    timestamps()
  end

  @required_fields [:email]
  @optional_fields [:name, :is_admin]
  @doc """
  Builds a changeset based on the `struct` and `params`.
  """
  def changeset(struct, params \\ %{}) do
    struct
    |> cast(params, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
  end

  @doc """
  Build a changeset for registration.
  Validates password and ensures it gets hashed.
  """
  def registration_changeset(struct, params) do
    struct
    |> changeset(params)
    |> cast(params, [:password], [])
    |> validate_length(:password, min: 6, max: 100)
    |> hash_password
  end

  @doc """
  Adds the hashed password to the changeset.
  """
  defp hash_password(changeset) do
    case changeset do
      # If it's a valid password, grab (by matching) the password,
      # change the changeset by inserting the hashed password.
      %Ecto.Changeset{valid?: true, changes: %{password: password}} ->
        put_change(changeset, :password_hash, Comeonin.Bcrypt.hashpwsalt(password))
      # Anything else (eg. not valid), return untouched.
      _ -> changeset
    end
  end
end
