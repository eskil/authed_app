# User and Admin auth with ex machina tests

I'm going to go through [this excellent blog post by Andrei
Chernykh](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#.i4w5d87sl)
to setup a phoenix app with user/admin auth.

Then I'll extend the project by adding json API endpoints and
unit-tests using ex machina.

# Let's begin

Since the first large part is going through Andrei Chernykh's
post, I'll keep this bit short and less detailed than his
excellent post. For the sake of forcing myself to actually write
all the things, I'm renaming the app from `simple_auth` to
`authed_app` and skipping the post models.

I recommend reading his blog post, and if you follow that, you
can basically skip to [the next chapter](#ex-machina-tests).

## Start a phoenix project

Create a project
```bash
mix phoenix.new authed_app
mix ecto.create
cd authed_app
git init .
git add .
git commit -m "Initial commit."
```

## Add user model

Create the user model with a bool for admin flag.
```bash
mix phoenix.gen.model User users email:string name:string password_hash:string is_admin:boolean
```

Edit as per the blog;
```diff
diff --git a/priv/repo/migrations/20170220211113_create_user.exs b/priv/repo/migrations/20170220211113_create_user.exs
index 660cc3f..fe44a7b 100644
--- a/priv/repo/migrations/20170220211113_create_user.exs
+++ b/priv/repo/migrations/20170220211113_create_user.exs
@@ -3,7 +3,7 @@ defmodule AuthedApp.Repo.Migrations.CreateUser do

   def change do
     create table(:users) do
-      add :email, :string
+      add :email, :string, null: false
       add :name, :string
       add :password_hash, :string
       add :is_admin, :boolean, default: false, null: false
@@ -11,5 +11,6 @@ defmodule AuthedApp.Repo.Migrations.CreateUser do
       timestamps()
     end

+    create unique_index(:users, [:email])
   end
 end
```

And fix up the user model
```diff
diff --git a/web/models/user.ex b/web/models/user.ex
index 2c7f823..48fb451 100644
--- a/web/models/user.ex
+++ b/web/models/user.ex
@@ -4,18 +4,21 @@ defmodule AuthedApp.User do
   schema "users" do
     field :email, :string
     field :name, :string
+    field :password, :string, virtual: true
     field :password_hash, :string
     field :is_admin, :boolean, default: false

     timestamps()
   end

+  @required_fields ~w(email)a
+  @optional_fields ~w(name is_admin)a
   @doc """
   Builds a changeset based on the `struct` and `params`.
   """
   def changeset(struct, params \\ %{}) do
     struct
-    |> cast(params, [:email, :name, :password_hash, :is_admin])
-    |> validate_required([:email, :name, :password_hash, :is_admin])
+    |> cast(params, @required_fields ++ @optional_fields)
+    |> validate_required(@required_fields)
   end
 end
```

Run migration to create db
```bash
mix ecto.migrate
```

Add the initial user controller in `web/controllers/user_controller.ex`
```elixir
defmodule AuthedApp.UserController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  def show(conn, %{"id" => id}) do
    user = Repo.get!(User, id)
    render(conn, "show.html", user: user)
  end

  def new(conn, _params) do
    changeset = User.changeset(%User{})
    render(conn, "new.html", changeset: changeset)
  end

  def create(conn, %{"user" => user_params}) do
    # tbd
  end
end
```

And a route to the resource
```diff
diff --git a/web/router.ex b/web/router.ex
index 329c6c4..2c8b88f 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -17,6 +17,8 @@ defmodule AuthedApp.Router do
     pipe_through :browser # Use the default browser stack

     get "/", PageController, :index
+
+    resources "/users", UserController, only: [:show, :new, :create]
   end

   # Other scopes may use custom stacks.
```

And the view class in `web/views/user_view.ex`
```elixir
defmodule AuthedApp.UserView do
  use AuthedApp.Web, :view
end
```

And some basic templates, `web/templates/user/show.html.eex`
```html
<h2><%= @user.name %></h2>
<p><%= @user.email %></p>
```

`web/templates/new.html.eex`
```html
<h1>User Registration</h1>
<%= form_for @changeset, user_path(@conn, :create), fn f -> %>
  <%= if @changeset.action do %>
    <div class="alert alert-danger">
      <p>There are some errors</p>
    </div>
  <% end %>
  <div class="form-group">
    <%= text_input f, :email, placeholder: "Email",
                              class: "form-control" %>
    <%= error_tag f, :email %>
  </div>
  <div class="form-group">
    <%= text_input f, :name, placeholder: "Name",
                             class: "form-control" %>
    <%= error_tag f, :name %>
  </div>
  <div class="form-group">
    <%= password_input f, :password, placeholder: "Password",
                                     class: "form-control" %>
    <%= error_tag f, :password %>
  </div>
  <%= submit "Create User", class: "btn btn-primary" %>
<% end %>
```

Add links to registration in the header instead of "get started" in `web/templates/layout/app.html.eex
```diff
diff --git a/web/templates/layout/app.html.eex b/web/templates/layout/app.html.eex
index 7b4e9de..5f9a640 100644
--- a/web/templates/layout/app.html.eex
+++ b/web/templates/layout/app.html.eex
@@ -16,7 +16,7 @@
       <header class="header">
         <nav role="navigation">
           <ul class="nav nav-pills pull-right">
-            <li><a href="http://www.phoenixframework.org/docs">Get Started</a></li>
+            <%= link "Register", to: user_path(@conn, :new) %>
           </ul>
         </nav>
         <span class="logo"></span>
```

## Session controller.

This next part of Andrei's blog is where we add the session
controller, including password hasing etc.

For hasing, add `comeonin` to `./mix.exs`
```diff
diff --git a/mix.exs b/mix.exs
index b488bd0..efc5070 100644
--- a/mix.exs
+++ b/mix.exs
@@ -19,7 +19,7 @@ defmodule AuthedApp.Mixfile do
   def application do
     [mod: {AuthedApp, []},
      applications: [:phoenix, :phoenix_pubsub, :phoenix_html, :cowboy, :logger, :gettext,
-                    :phoenix_ecto, :postgrex]]
+                    :phoenix_ecto, :postgrex, :comeonin]]
   end

   # Specifies which paths to compile per environment.
@@ -37,7 +37,8 @@ defmodule AuthedApp.Mixfile do
      {:phoenix_html, "~> 2.6"},
      {:phoenix_live_reload, "~> 1.0", only: :dev},
      {:gettext, "~> 0.11"},
-     {:cowboy, "~> 1.0"}]
+     {:cowboy, "~> 1.0"},
+     {:comeonin, "~> 2.5"}]
   end

   # Aliases are shortcuts or tasks specific to the current project.
```

We add a specific changeset for registrations to `web/models/user.ex`
that uses comeonin to bcrypt the stored password.

```diff
diff --git a/web/models/user.ex b/web/models/user.ex
index 48fb451..741a73f 100644
--- a/web/models/user.ex
+++ b/web/models/user.ex
@@ -21,4 +21,30 @@ defmodule AuthedApp.User do
     |> cast(params, @required_fields ++ @optional_fields)
     |> validate_required(@required_fields)
   end
+
+  @doc """
+  Build a changeset for registration.
+  Validates password and ensures it gets hashed.
+  """
+  def registration_changeset(struct, params) do
+    struct
+    |> changeset(params)
+    |> cast(params, [:password], [])
+    |> validate_length(:password, min: 6, max: 100)
+    |> hash_password
+  end
+
+  @doc """
+  Adds the hashed password to the changeset.
+  """
+  defp hash_password(changeset) do
+    case changeset do
+      # If it's a valid password, grab (by matching) the password,
+      # change the changeset by inserting the hashed password.
+      %Ecto.Changeset{valid?: true, changes: %{password: password}} ->
+        put_change(changeset, :password_hash, Comeonin.Bcrypt.hashpwsalt(password))
+      # Anything else (eg. not valid), return untouched.
+      _ -> changeset
+    end
+  end
 end
```

Change user controller in `web/controllers/user_controller.ex` to check for (and scrub) a `user` param on create, and then make the `create` method use
the `registration_changeset`
```diff
diff --git a/web/controllers/user_controller.ex b/web/controllers/user_controller.ex
index d81aa75..a1c60db 100644
--- a/web/controllers/user_controller.ex
+++ b/web/controllers/user_controller.ex
@@ -3,6 +3,10 @@ defmodule AuthedApp.UserController do

   alias AuthedApp.User

+  # https://hexdocs.pm/phoenix/Phoenix.Controller.html#scrub_params/2
+  # This plug checks we have a "user" key and converts empty strings to nils.
+  plug :scrub_params, "user" when action in [:create]
+
   def show(conn, %{"id" => id}) do
     user = Repo.get!(User, id)
     render(conn, "show.html", user: user)
```

```diff
diff --git a/web/controllers/user_controller.ex b/web/controllers/user_controller.ex
index a1c60db..bbe66e7 100644
--- a/web/controllers/user_controller.ex
+++ b/web/controllers/user_controller.ex
@@ -18,6 +18,14 @@ defmodule AuthedApp.UserController do
   end

   def create(conn, %{"user" => user_params}) do
-    # tbd
+    changeset = User.registration_changeset(%User{}, user_params)
+    case Repo.insert(changeset) do
+      {:ok, user} ->
+        conn
+        |> put_flash(:info, "#{user.name} created!")
+        |> redirect(to: user_path(conn, :show, user))
+      {:error, changeset} ->
+        render(conn, "new.html", changeset: changeset)
+    end
   end
 end
```

We are now
(here)[https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#ef37]
and can register users with hashed passwords.

# Ex Machina Tests
