defmodule AuthedApp.Router do
  use AuthedApp.Web, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  pipeline :with_session do
    plug Guardian.Plug.VerifySession
    plug Guardian.Plug.LoadResource
    plug AuthedApp.CurrentUser
  end


  scope "/", AuthedApp do
    pipe_through [:browser, :with_session]

    get "/", PageController, :index

    resources "/users", UserController, only: [:show, :new, :create]

    resources "/sessions", SessionController, only: [:new, :create, :delete]
  end

  # Other scopes may use custom stacks.
  # scope "/api", AuthedApp do
  #   pipe_through :api
  # end
end
