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

  pipeline :user_required do
  end

  pipeline :admin_required do
  end

  scope "/", AuthedApp do
    pipe_through [:browser, :with_session]

    # Public routes.
    get "/", PageController, :index
    get "/news", NewsController, :index
    resources "/users", UserController, only: [:show, :new, :create]
    resources "/sessions", SessionController, only: [:new, :create, :delete]

    scope "/" do
      # Login required.
      pipe_through [:user_required]
      get "/info", InfoController, :index

      scope "/admin", Admin, as: :admin do
        # Admin account required
        pipe_through [:admin_required]
        resources "/users", UserController, only: [:index]
      end
    end
  end

  # Other scopes may use custom stacks.
  # scope "/api", AuthedApp do
  #   pipe_through :api
  # end
end
