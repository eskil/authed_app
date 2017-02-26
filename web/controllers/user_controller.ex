defmodule AuthedApp.UserController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  # https://hexdocs.pm/phoenix/Phoenix.Controller.html#scrub_params/2
  # This plug checks we have a "user" key and converts empty strings to nils.
  plug :scrub_params, "user" when action in [:create]

  def show(conn, %{"id" => id}) do
    user = Repo.get!(User, id)
    render(conn, "show.html", user: user)
  end

  def new(conn, _params) do
    changeset = User.changeset(%User{})
    render(conn, "new.html", changeset: changeset)
  end

  def create(conn, %{"user" => user_params}) do
    changeset = User.registration_changeset(%User{}, user_params)
    case Repo.insert(changeset) do
      {:ok, user} ->
        conn
        |> AuthedApp.Auth.login(user)
        |> put_flash(:info, "#{user.name} created!")
        |> redirect(to: user_path(conn, :show, user))
      {:error, changeset} ->
        render(conn, "new.html", changeset: changeset)
    end
  end
end
