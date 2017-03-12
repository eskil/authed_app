defmodule AuthedApp.API.V1.SessionController do
  use AuthedApp.Web, :controller

  import AuthedApp.ChangesetErrors
  alias AuthedApp.API.V1.LoginParams

  def login(conn, params) do
    changeset = LoginParams.changeset(%LoginParams{}, params)
    case changeset do
      %{:params => p, :valid? => true} ->
        case AuthedApp.Auth.login_by_email_and_password(conn, p["email"], p["password"], format: get_format(conn)) do
          {:ok, conn} ->
            jwt = Guardian.Plug.current_token(conn)
            {:ok, claims} = Guardian.Plug.claims(conn)
            exp = Map.get(claims, "exp")

            conn
            |> put_resp_header("authorization", "#{jwt}")
            |> put_resp_header("x-expires", "#{exp}")
            |> render("login.json", status: :ok)
          {:error, reason, conn} ->
            conn
            |> put_status(:forbidden)
            |> render("login.json", status: :failed)
        end
      _ ->
        conn
        |> put_status(400)
        |> render("login.json",
                  status: :error,
                  messages: changeset_errors(changeset),
                  errors: changeset_errors_as_dict(changeset))
    end
  end
end
