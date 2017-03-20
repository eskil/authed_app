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

  pipeline :with_api_session do
    plug Guardian.Plug.VerifyHeader
    plug Guardian.Plug.LoadResource
    plug AuthedApp.CurrentUser
  end

  pipeline :login_required do
    plug Guardian.Plug.EnsureAuthenticated, handler: AuthedApp.GuardianErrorHandler
  end

  pipeline :admin_required do
    plug Guardian.Plug.EnsureAuthenticated, handler: AuthedApp.Admin.GuardianErrorHandler
    plug AuthedApp.CheckAdmin
  end

  pipeline :api_login_required do
    plug Guardian.Plug.EnsureAuthenticated, handler: Guardian.Plug.ErrorHandler
  end

  pipeline :api_admin_required do
    plug Guardian.Plug.EnsureAuthenticated, handler: Guardian.Plug.ErrorHandler
    plug AuthedApp.CheckAdmin
  end

  scope "/", AuthedApp do
    pipe_through [:browser, :with_session]

    # Public routes.
    get "/", PageController, :index
    resources "/users", UserController, only: [:show, :new, :create]
    resources "/sessions", SessionController, only: [:new, :create, :delete]
    get "/public", PublicController, :index

    scope "/" do
      # Login required.
      pipe_through [:login_required]
      get "/private", PrivateController, :index
    end

    scope "/admin", Admin, as: :admin do
      # Admin account required
      pipe_through [:admin_required, :login_required]
      resources "/users", UserController, only: [:index]
    end
  end

  scope "/api", AuthedApp.API do
    pipe_through [:api, :with_api_session]
    scope "/v1", V1, as: :v1 do
      post "/signup", SessionController, :signup
      post "/login", SessionController, :login
      get "/logout", SessionController, :logout
      get "/public", PublicController, :index
      scope "/" do
        pipe_through [:api_login_required]
        get "/private", PrivateController, :index
      end
      scope "/admin", Admin, as: :admin do
        pipe_through [:api_admin_required]
        resources "/users", UserController, only: [:index]
      end
    end
  end
end
