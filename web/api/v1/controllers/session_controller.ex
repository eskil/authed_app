defmodule AuthedApp.API.V1.SessionController do
  use AuthedApp.Web, :controller

  import AuthedApp.Changesets
  alias AuthedApp.User
  alias AuthedApp.API.V1.LoginParams

  def signup(conn, params) do
    changeset = User.registration_changeset(%User{}, params)
    case Repo.insert(changeset) do
      {:ok, user} ->
        conn
        |> AuthedApp.Auth.login(user, :json)
        |> put_status(201)
        |> render("login.json")
      _ ->
        conn
        |> put_status(400)
        |> render("error.json", errors: errors_to_dict(changeset))
    end
  end

  def login(conn, params) do
    changeset = LoginParams.changeset(%LoginParams{}, params)
    case changeset do
      %{:params => p, :valid? => true} ->
        case AuthedApp.Auth.login_by_email_and_password(conn, p["email"], p["password"]) do
          {:ok, conn} ->
            conn
            |> render("login.json")
          {:error, _reason, conn} ->
            conn
            |> put_status(:forbidden)
            |> render("login.json")
        end
      _ ->
        conn
        |> put_status(400)
        |> render("error.json", errors: errors_to_dict(changeset))
    end
  end
end
