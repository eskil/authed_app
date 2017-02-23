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

Create a new blank project and do your initial commit.

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

As per the blog, edit the db migration to requre email and create a
unique index on emails.

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

Fix up the user model to have a virtual (non-db-backed) password field, and tweak the changeset to clearly list out optiona and required fields.

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

+  @required_fields [:email]
+  @optional_fields [:name, :is_admin]
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

Run migration to create the db and users table.

```bash
mix ecto.migrate
```

## User controller

Add the initial user controller in
`web/controllers/user_controller.ex` to handle creating users.

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

And a route to the users resource.

```diff
diff --git a/web/router.ex b/web/router.ex
index 329c6c4..8c3e8a2 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -17,6 +17,7 @@ defmodule AuthedApp.Router do
     pipe_through :browser # Use the default browser stack

     get "/", PageController, :index
+    resources "/users", UserController, only: [:show, :new, :create]
   end

   # Other scopes may use custom stacks.
```

## User registration form

Add a view class in `web/views/user_view.ex` for user related matters.

```elixir
defmodule AuthedApp.UserView do
  use AuthedApp.Web, :view
end
```

And some basic templates. `web/templates/user/show.html.eex` to show user info.

```html
<h2><%= @user.name %></h2>
<p><%= @user.email %></p>
```

and `web/templates/new.html.eex` which is our registration form.

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

Add links to registration in the header instead of "get started" in
`web/templates/layout/app.html.eex

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
+            <li><%= link "Register", to: user_path(@conn, :new) %></li>
           </ul>
         </nav>
         <span class="logo"></span>
```

## Registration

This next part of Andrei's blog is where we add the registration code
path, including password hashing and validation.

For hasing, add [comeonin](https://github.com/riverrun/comeonin) to `./mix.exs`

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
+    |> cast(params, [:password])
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

Change user controller in `web/controllers/user_controller.ex` to
check for (and scrub) a `user` parameter on create, and then make the
`create` method use the `registration_changeset`

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
[here in Andrei's blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#ef37)
and can register users with hashed passwords.


# Session controller

Sessions are managed by `new` which is the login form, `create` which
is a login form submit and `delete` which is the logout.

Add the SessionController in `web/controllers/session_controller.ex`.

```elixir
defmodule AuthedApp.SessionController do
  use AuthedApp.Web, :controller

  plug :scrub_params, "session" when action in [:create]

  def new(conn, _params) do
    render(conn, "new.html")
  end

  def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
    # tbd
  end

  def delete(conn, _params) do
    # tbd
  end
end
```

a corresponding view module in `web/views/session_view.ex`

```elixir
defmodule AuthedApp.SessionView do
  use AuthedApp.Web, :view
end
```

and the login form in `web/templates/session/new.html.eex`:

```html
<h1>Sign in</h1>
<%= form_for @conn, session_path(@conn, :create),
                                          [as: :session], fn f -> %>
  <div class="form-group">
    <%= text_input f, :email, placeholder: "Email",
                              class: "form-control" %>
  </div>
  <div class="form-group">
    <%= password_input f, :password, placeholder: "Password",
                                     class: "form-control" %>
  </div>
  <%= submit "Sign in", class: "btn btn-primary" %>
<% end %>
```

Finally add the controller to routing in `web/router.ex`.

```diff
diff --git a/web/router.ex b/web/router.ex
index 8c3e8a2..380cab7 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -18,6 +18,7 @@ defmodule AuthedApp.Router do

     get "/", PageController, :index
     resources "/users", UserController, only: [:show, :new, :create]
+    resources "/sessions", SessionController, only: [:new, :create, :delete]
   end

   # Other scopes may use custom stacks.
```

We can test it by calling curl to get the login page (and the csrf
token that phoenix inserts).

Start the service
```bash
mix phoenix.server
```

Get the login page plus cookie and csrf token

```bash
curl -X GET --cookie-jar ~/.cookiejar --verbose  localhost:4000/sessions/new
...
<form accept-charset="UTF-8" action="/sessions" method="post">
  <input name="_csrf_token" type="hidden"
   value="eVJ4HyFrRScdUA01SHVuaAEXbDI0JgAALgOHsS1qs14Vp8+P2d9CYw==">
  <input name="_utf8" type="hidden" value="✓">
  <div class="form-group">
    <input class="form-control" id="session_email" name="session[email]" placeholder="Email" type="text">
  </div>
  <div class="form-group">
    <input class="form-control" id="session_password" name="session[password]" placeholder="Password" type="password">
  </div>
  <button class="btn btn-primary" type="submit">Sign in</button>
</form>
```

```bash
curl -H "X-HTTP-Method-Override: POST" -H "x-csrf-token: eVJ4HyFrRScdUA01SHVuaAEXbDI0JgAALgOHsS1qs14Vp8+P2d9CYw==" -X POST -F 'session[email]=test1@example.com' -F 'session[password]=PASSWORD'  --cookie ~/.cookiejar --verbose  localhost:4000/sessions
```

This will end with a crash since SessionController's `create` isn't implemented yet:
```
[error] #PID<0.463.0> running AuthedApp.Endpoint terminated
Server: localhost:4000 (http)
Request: POST /sessions
** (exit) an exception was raised:
    ** (RuntimeError) expected action/2 to return a Plug.Conn, all plugs must receive a
       connection (conn) and return a connection
```

Extend the app layout to include a signon link in `web/templates/layout/app.html.eex`.

```diff
diff --git a/web/templates/layout/app.html.eex b/web/templates/layout/app.html.eex
index c3bce30..1837e66 100644
--- a/web/templates/layout/app.html.eex
+++ b/web/templates/layout/app.html.eex
@@ -17,6 +17,7 @@
         <nav role="navigation">
           <ul class="nav nav-pills pull-right">
             <li><%= link "Register", to: user_path(@conn, :new) %></li>
+            <li><%= link "Sign in", to: session_path(@conn, :new) %></li>
           </ul>
         </nav>
         <span class="logo"></span>
```

## Implement login with Guardian

We are now [here in Andrei's
blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#2334)
and ready to add [Guardian](https://github.com/ueberauth/guardian) to
our project, and implement signing in.

Add guardian to `./mix.exs`:

```diff
diff --git a/mix.exs b/mix.exs
index efc5070..fa593ef 100644
--- a/mix.exs
+++ b/mix.exs
@@ -38,7 +38,8 @@ defmodule AuthedApp.Mixfile do
      {:phoenix_live_reload, "~> 1.0", only: :dev},
      {:gettext, "~> 0.11"},
      {:cowboy, "~> 1.0"},
-     {:comeonin, "~> 2.5"}]
+     {:comeonin, "~> 2.5"},
+     {:guardian, "~> 0.14"}]
   end

   # Aliases are shortcuts or tasks specific to the current project.
```

Add a section to `config/dev.exs` to configure Guardian. Without this
`iex` will fail since Guardian needs a config section.

```elixir
config :guardian, Guardian,
 issuer: "AuthedApp.#{Mix.env}",
 ttl: {30, :days},
 verify_issuer: true,
 serializer: AuthedApp.GuardianSerializer,
 secret_key: to_string(Mix.env) <> "some secret for now"
```

You can now generate a better secret key, and/or add a
`config/prod.exs` with a production specific key. To generate the key,
launch `iex -S mix` and call [JOSE.JWK](https://github.com/bryanjos/joken) directly.

```bash
Interactive Elixir (1.4.1) - press Ctrl+C to exit (type h() ENTER for help)
iex(1)> JOSE.JWK.generate_key({:ec, "P-521"}) |> JOSE.JWK.to_map |> elem(1)
%{"crv" => "P-521",
  "d" => "Xp-xQ-zuy6hEKn5QNnyDxk6S9ZiB2LExXG8wXOrt0bl7JCbiirg73i5sS20iovPUofxXrekmejVEIpfdN4S7HJg",
  "kty" => "EC",
  "x" => "Abj7h0Yz_70RR3YudNnAKGRKwT6axraxC7427db_OvWVQam-plI6HDs15UwydtGv4mAtMsWmmK9c3Wvrmgwm9U_V",
  "y" => "ARI0t4q-v8qiTksOrCtEgHYFFxvgOAMXOnino8lgsVurFWRZK_6ibmqLSEQaIkk1K22noH28gVICL28m09OXVuH3"}
iex(2)> JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map |> elem(1)
%{"k" => "Bvmi7pm61u-7FYNHw8sR7VaAwyJQboCDPXdWBS3Lxxc", "kty" => "oct"}
iex(3)>
```

YMMV on what kind of key you want to use, we'll just use the 32 oct
key (the latter)for now, so `config/dev.exs` ends up like

```elixir
config :guardian, Guardian,
 issuer: "AuthedApp.#{Mix.env}",
 ttl: {30, :days},
 verify_issuer: true,
 serializer: AuthedApp.GuardianSerializer,
 secret_key: %{"k" => "Bvmi7pm61u-7FYNHw8sR7VaAwyJQboCDPXdWBS3Lxxc", "kty" => "oct"}
```

Finally we add the GuardianSerializer module in `web/auth/guardian_serializer.ex`. This is pretty stock from the [guardian readme](https://github.com/ueberauth/guardian#serializer).

```elixir
defmodule AuthedApp.GuardianSerializer do
  @behaviour Guardian.Serializer

  alias AuthedApp.Repo
  alias AuthedApp.User

  def for_token(user = %User{}), do: {:ok, "User:#{user.id}"}
  def for_token(_), do: {:error, "Unknown resource type"}

  def from_token("User:" <> id), do: {:ok, Repo.get(User, id)}
  def from_token(_), do: {:error, "Unknown resource type"}
end
```

Hook up SessionController's `create` in
`web/controllers/session_controller.ex` to let users log in if their
password is verified.

```diff
diff --git a/web/controllers/session_controller.ex b/web/controllers/session_controller.ex
index e42aaa9..9cbc592 100644
--- a/web/controllers/session_controller.ex
+++ b/web/controllers/session_controller.ex
@@ -1,6 +1,10 @@
 defmodule AuthedApp.SessionController do
   use AuthedApp.Web, :controller

+  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]
+
+  alias AuthedApp.User
+
   plug :scrub_params, "session" when action in [:create]

   def new(conn, _params) do
@@ -8,7 +12,37 @@ defmodule AuthedApp.SessionController do
   end

   def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
-    # tbd
+    # Get user by email
+    user = Repo.get_by(User, email: email)
+
+    result = cond do
+      # We have a user and the hashed password matches the db one.
+      user && checkpw(password, user.password_hash) ->
+        {:ok, login(conn, user)}
+      # We have a user but the password check failed.
+      user ->
+        {:error, :unauthorized, conn}
+      # Didn't find the email, call dummy_checkpw to fake delay.
+      true ->
+        dummy_checkpw()
+        {:error, :not_found, conn}
+    end
+
+    case result do
+      {:ok, conn} ->
+        conn
+        |> put_flash(:info, "You're logged in")
+        |> redirect(to: page_path(conn, :index))
+      {:error, _reason, conn} ->
+        conn
+        |> put_flash(:error, "Invalid email or password")
+        |> render("new.html")
+    end
+  end
+
+  defp login(conn, user) do
+    conn
+    |> Guardian.Plug.sign_in(user)
   end

   def delete(conn, _params) do
```

Now we add the most excellent `current_user` plug from the blog post in `web/auth/current_user.ex`:

```elixir
defmodule AuthedApp.CurrentUser do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    assign(conn, :current_user, Guardian.Plug.current_resource(conn))
  end
end
```

and connect it in a pipeline in `web/router.ex` that also calls the
other Guardian plugs to verify the session and load the user.

```diff
diff --git a/web/router.ex b/web/router.ex
index 380cab7..f55202a 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -13,8 +13,14 @@ defmodule AuthedApp.Router do
     plug :accepts, ["json"]
   end

+  pipeline :with_session do
+    plug Guardian.Plug.VerifySession
+    plug Guardian.Plug.LoadResource
+    plug AuthedApp.CurrentUser
+  end
+
   scope "/", AuthedApp do
-    pipe_through :browser # Use the default browser stack
+    pipe_through [:browser, :with_session]

     get "/", PageController, :index
     resources "/users", UserController, only: [:show, :new, :create]
```

And then the sign-out by implementing SessionController's `delete` in `web/controllers/session_controller.ex`

```diff
diff --git a/web/controllers/session_controller.ex b/web/controllers/session_controller.ex
index 9cbc592..268caa2 100644
--- a/web/controllers/session_controller.ex
+++ b/web/controllers/session_controller.ex
@@ -46,6 +46,13 @@ defmodule AuthedApp.SessionController do
   end

   def delete(conn, _params) do
-    # tbd
+    conn
+    |> logout
+    |> put_flash(:info, "Logged out")
+    |> redirect(to: page_path(conn, :index))
+  end
+
+  defp logout(conn) do
+    Guardian.Plug.sign_out(conn)
   end
 end
```

And we leverage the `AuthedApp.CurrentUser` plug to use the `@current_user` in `web/templates/layout/app.html.eex` to differentiate between signed in and out sessions.

```diff
diff --git a/web/templates/layout/app.html.eex b/web/templates/layout/app.html.eex
index 1837e66..6e61e12 100644
--- a/web/templates/layout/app.html.eex
+++ b/web/templates/layout/app.html.eex
@@ -16,8 +16,13 @@
       <header class="header">
         <nav role="navigation">
           <ul class="nav nav-pills pull-right">
-            <li><%= link "Register", to: user_path(@conn, :new) %></li>
-            <li><%= link "Sign in", to: session_path(@conn, :new) %></li>
+            <%= if @current_user do %>
+              <li><%= @current_user.name %> (<%= @current_user.email %>)</li>
+              <li><%= link("Sign out", to: session_path(@conn, :delete, @current_user), method: "delete") %></li>
+            <%= else %>
+              <li><%= link "Register", to: user_path(@conn, :new) %></li>
+              <li><%= link "Sign in", to: session_path(@conn, :new) %></li>
+            <%= end %>
           </ul>
         </nav>
         <span class="logo"></span>
```

## Refactoring

We're now
[here in the blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#6687).

We'll refactor SessionController's `login` and `logout` to enable
logging in when registering. Move `login` and `logout` to
`web/auth/auth.ex` and add `login_by_email_and_password`.

```elixir
defmodule AuthedApp.Auth do
  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]

  alias AuthedApp.Repo
  alias AuthedApp.User

  def login(conn, user) do
    conn
    |> Guardian.Plug.sign_in(user)
  end

  def logout(conn) do
    Guardian.Plug.sign_out(conn)
  end

  def login_by_email_and_password(conn, email, password) do
    # Get user by email
    user = Repo.get_by(User, email: email)

    cond do
      # We have a user and the hashed password matches the db one.
      user && checkpw(password, user.password_hash) ->
        {:ok, login(conn, user)}
      # We have a user but the password check failed.
      user ->
        {:error, :unauthorized, conn}
      # Didn't find the email, call dummy_checkpw to fake delay.
      true ->
        dummy_checkpw()
        {:error, :not_found, conn}
    end
  end
end
```

Trim down `web/controllers/session_controller.ex` to call the new module.

```diff
diff --git a/web/controllers/session_controller.ex b/web/controllers/session_controller.ex
index 268caa2..042e0f3 100644
--- a/web/controllers/session_controller.ex
+++ b/web/controllers/session_controller.ex
@@ -1,8 +1,6 @@
 defmodule AuthedApp.SessionController do
   use AuthedApp.Web, :controller

-  import Comeonin.Bcrypt, only: [checkpw: 2, dummy_checkpw: 0]
-
   alias AuthedApp.User

   plug :scrub_params, "session" when action in [:create]
@@ -12,26 +10,10 @@ defmodule AuthedApp.SessionController do
   end

   def create(conn, %{"session" => %{"email" => email, "password" => password}}) do
-    # Get user by email
-    user = Repo.get_by(User, email: email)
-
-    result = cond do
-      # We have a user and the hashed password matches the db one.
-      user && checkpw(password, user.password_hash) ->
-        {:ok, login(conn, user)}
-      # We have a user but the password check failed.
-      user ->
-        {:error, :unauthorized, conn}
-      # Didn't find the email, call dummy_checkpw to fake delay.
-      true ->
-        dummy_checkpw()
-        {:error, :not_found, conn}
-    end
-
-    case result do
+    case AuthedApp.Auth.login_by_email_and_password(conn, email, password) do
       {:ok, conn} ->
         conn
-        |> put_flash(:info, "You're logged in")
+        |> put_flash(:info, "You're signed in")
         |> redirect(to: page_path(conn, :index))
       {:error, _reason, conn} ->
         conn
@@ -40,19 +22,10 @@ defmodule AuthedApp.SessionController do
     end
   end

-  defp login(conn, user) do
-    conn
-    |> Guardian.Plug.sign_in(user)
-  end
-
   def delete(conn, _params) do
     conn
-    |> logout
+    |> AuthedApp.Auth.logout
     |> put_flash(:info, "Logged out")
     |> redirect(to: page_path(conn, :index))
   end
-
-  defp logout(conn) do
-    Guardian.Plug.sign_out(conn)
-  end
 end
```

And tweak UserController to sign in the user right after creating in `web/controllers/user_controller.ex`

```diff
diff --git a/web/controllers/user_controller.ex b/web/controllers/user_controller.ex
index bbe66e7..5b36fa1 100644
--- a/web/controllers/user_controller.ex
+++ b/web/controllers/user_controller.ex
@@ -22,6 +22,7 @@ defmodule AuthedApp.UserController do
     case Repo.insert(changeset) do
       {:ok, user} ->
         conn
+        |> AuthedApp.Auth.login(user)
         |> put_flash(:info, "#{user.name} created!")
         |> redirect(to: user_path(conn, :show, user))
       {:error, changeset} ->
```



## Session specific pages

We are now [now here in the
blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#b9df),
and we'll start to deviate slightly. I won't be adding the posts
models etc, only the signed in/not signed in/admin distinction.

  * A `/news` page available to all.
  * A `/info` page only available to signed in users.
  * A `/users` page that lists all users, only available to admins.

These will be available from the front page, where we'll replace the
"Resources" and "Help" lists with a single "Pages" list. And this list
will only show the links available given the current session.

We already have a UserController that can list the users for the
`/user` endpoint. We'll add two controllers for `/news` and `/info`.

In `web/controllers/news_controller.ex` (note, you could use `mix
phoenix.gen.html` for a lot of this, but keeping this explicit).

```elixir
defmodule AuthedApp.NewsController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
```

it's corresponding view module in `/web/views/news_view.ex`
```elixir
defmodule AuthedApp.NewsView do
  use AuthedApp.Web, :view
end
```

and the template in `web/templates/news/index.html.eex`

```html
<h2>News</h2>
<p>No news today</p>
```

and connect it's route in `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index f55202a..f6cbcd3 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -25,6 +25,7 @@ defmodule AuthedApp.Router do
     get "/", PageController, :index
     resources "/users", UserController, only: [:show, :new, :create]
     resources "/sessions", SessionController, only: [:new, :create, :delete]
+    get "/news", NewsController, :index
   end

   # Other scopes may use custom stacks.
```

Do the same for an InfoController, add it to `web/controllers/info_controller.ex`

```elixir
defmodule AuthedApp.InfoController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
```

it's corresponding view module in `/web/views/info_view.ex`

```elixir
defmodule AuthedApp.InfoView do
  use AuthedApp.Web, :view
end
```

and the template in `web/templates/info/index.html.eex`

```html
<h2>Info</h2>
<p>No info today</p>
```

and connect it's route in `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index f6cbcd3..d6ba8c7 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -26,6 +26,7 @@ defmodule AuthedApp.Router do
     resources "/users", UserController, only: [:show, :new, :create]
     resources "/sessions", SessionController, only: [:new, :create, :delete]
     get "/news", NewsController, :index
+    get "/info", InfoController, :index
   end

   # Other scopes may use custom stacks.
```

Add the `/users` index endpoint to list users, first we add the handler to UserController in `web/controllers/user_controller.ex`

```diff
diff --git a/web/controllers/user_controller.ex b/web/controllers/user_controller.ex
index 5b36fa1..2719bf7 100644
--- a/web/controllers/user_controller.ex
+++ b/web/controllers/user_controller.ex
@@ -29,4 +29,8 @@ defmodule AuthedApp.UserController do
         render(conn, "new.html", changeset: changeset)
     end
   end
+
+  def index(conn, _params) do
+    render(conn, "index.html", users: Repo.all(User))
+  end
 end
```

the index template in `web/templates/users/index.html.eex`

```html
<h2>Users</h2>

<ul>
  <%= for user <- @users do %>
      <li><%= user.name %> (<%= user.email %>)</li>
  <% end %>
</ul>
```

and connect the route in `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index d6ba8c7..6828f92 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -23,7 +23,7 @@ defmodule AuthedApp.Router do
     pipe_through [:browser, :with_session]

     get "/", PageController, :index
-    resources "/users", UserController, only: [:show, :new, :create]
+    resources "/users", UserController, only: [:show, :new, :create, :index]
     resources "/sessions", SessionController, only: [:new, :create, :delete]
     get "/news", NewsController, :index
     get "/info", InfoController, :index
```

Now we all the endpoints but not authorisation checks.


# Authorisation checks on pages

We're still [here in the
blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#b9df),
and now resume adding the three kinds of authorisation.

We first rearrange our routes so we can use specific pipelines and also put some endpoints behind a `/admin` prefix which is nice.

```bash
$ mix phoenix.routes
   page_path  GET     /              AuthedApp.PageController :index
   user_path  GET     /users         AuthedApp.UserController :index
   user_path  GET     /users/new     AuthedApp.UserController :new
   user_path  GET     /users/:id     AuthedApp.UserController :show
   user_path  POST    /users         AuthedApp.UserController :create
session_path  GET     /sessions/new  AuthedApp.SessionController :new
session_path  POST    /sessions      AuthedApp.SessionController :create
session_path  DELETE  /sessions/:id  AuthedApp.SessionController :delete
   news_path  GET     /news          AuthedApp.NewsController :index
   info_path  GET     /info          AuthedApp.InfoController :index
```

We add two pipelines (`admin_required` and `login_required`) and
rearrange routes in `web/router.ex` so they're in the right
pipelines. Note they're nested.

```diff
diff --git a/web/router.ex b/web/router.ex
index 8951803..3cf3592 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -19,17 +19,32 @@ defmodule AuthedApp.Router do
     plug AuthedApp.CurrentUser
   end

+  pipeline :login_required do
+  end
+
+  pipeline :admin_required do
+  end

   scope "/", AuthedApp do
     pipe_through [:browser, :with_session]

-    get "/news", NewsController, :index
-    get "/info", InfoController, :index
+    # Public routes.
     get "/", PageController, :index
-
-    resources "/users", UserController, only: [:show, :new, :create, :index]
-
+    get "/news", NewsController, :index
+    resources "/users", UserController, only: [:show, :new, :create]
     resources "/sessions", SessionController, only: [:new, :create, :delete]
+
+    scope "/" do
+      # Login required.
+      pipe_through [:login_required]
+      get "/info", InfoController, :index
+
+      scope "/admin", Admin, as: :admin do
+        # Admin account required
+        pipe_through [:admin_required]
+        resources "/users", UserController, only: [:index]
+      end
+    end
   end

   # Other scopes may use custom stacks.
```

The routes now look like

```bash
$ mix phoenix.routes
      page_path  GET     /              AuthedApp.PageController :index
      news_path  GET     /news          AuthedApp.NewsController :index
      user_path  GET     /users/new     AuthedApp.UserController :new
      user_path  GET     /users/:id     AuthedApp.UserController :show
      user_path  POST    /users         AuthedApp.UserController :create
   session_path  GET     /sessions/new  AuthedApp.SessionController :new
   session_path  POST    /sessions      AuthedApp.SessionController :create
   session_path  DELETE  /sessions/:id  AuthedApp.SessionController :delete
      info_path  GET     /info          AuthedApp.InfoController :index
admin_user_path  GET     /admin/users   AuthedApp.Admin.UserController :index
```

Or in a diff

```diff
--- /tmp/routes	2017-02-22 07:48:56.000000000 -0800
+++ /tmp/routes-new	2017-02-22 07:48:11.000000000 -0800
@@ -1,5 +1,4 @@
       page_path  GET     /              AuthedApp.PageController :index
-      user_path  GET     /users         AuthedApp.UserController :index
       user_path  GET     /users/new     AuthedApp.UserController :new
       user_path  GET     /users/:id     AuthedApp.UserController :show
       user_path  POST    /users         AuthedApp.UserController :create
@@ -8,3 +7,4 @@
    session_path  DELETE  /sessions/:id  AuthedApp.SessionController :delete
       news_path  GET     /news          AuthedApp.NewsController :index
       info_path  GET     /info          AuthedApp.InfoController :index
+admin_user_path  GET     /admin/users   AuthedApp.Admin.UserController :index
```

Let's provide some links to this and remove some of the marketing
links in the standard template. First remove the `marketing` div from
`web/templates/page/index.html.eex`

```diff
diff --git a/web/templates/page/index.html.eex b/web/templates/page/index.html.eex
index 8ff4b81..956ce5e 100644
--- a/web/templates/page/index.html.eex
+++ b/web/templates/page/index.html.eex
@@ -2,35 +2,3 @@
   <h2><%= gettext "Welcome to %{name}", name: "Phoenix!" %></h2>
   <p class="lead">A productive web framework that<br />does not compromise speed and maintainability.</p>
 </div>
-
-<div class="row marketing">
-  <div class="col-lg-6">
-    <h4>Resources</h4>
-    <ul>
-      <li>
-        <a href="http://phoenixframework.org/docs/overview">Guides</a>
-      </li>
-      <li>
-        <a href="https://hexdocs.pm/phoenix">Docs</a>
-      </li>
-      <li>
-        <a href="https://github.com/phoenixframework/phoenix">Source</a>
-      </li>
-    </ul>
-  </div>
-
-  <div class="col-lg-6">
-    <h4>Help</h4>
-    <ul>
-      <li>
-        <a href="http://groups.google.com/group/phoenix-talk">Mailing list</a>
-      </li>
-      <li>
-        <a href="http://webchat.freenode.net/?channels=elixir-lang">#elixir-lang on freenode IRC</a>
-      </li>
-      <li>
-        <a href="https://twitter.com/elixirphoenix">@elixirphoenix</a>
-      </li>
-    </ul>
-  </div>
-</div>
```

and add some link buttons to the main app template, which wraps all our pages, in `web/templates/layout/app.html.eex`

```diff
diff --git a/web/templates/layout/app.html.eex b/web/templates/layout/app.html.eex
index 6e61e12..bd0633a 100644
--- a/web/templates/layout/app.html.eex
+++ b/web/templates/layout/app.html.eex
@@ -35,6 +35,20 @@
         <%= render @view_module, @view_template, assigns %>
       </main>

+      <div class="col-lg-6">
+        <h4>Resources</h4>
+        <ul>
+          <%= if @current_user do %>
+            <li>
+              <a href="/info">Info</a>
+            </li>
+          <%= end %>
+          <li>
+            <a href="/news">News</a>
+          </li>
+        </ul>
+      </div>
+
     </div> <!-- /container -->
     <script src="<%= static_path(@conn, "/js/app.js") %>"></script>
   </body>
```

Now if you access `/info` without being logged in, you should be
redirected to the login page, and you'll only see the `/info` link on
the home page if you're logged in.

I'll skip the `action/2` [over
ride]https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#cf42)
of a
[controller](https://hexdocs.pm/phoenix/Phoenix.Controller.html#summary)
that Andrei does, since I'm interested in the routing authorisation
aspects. But it's a good trick to know. Likewise we won't get into the
`resources` within `resources` part that he does.


## Implemention authorisation pipelines

We extend the `user_required` pipeline to call
[GuardianEnsureAuthenticated](https://github.com/ueberauth/guardian#guardianplugensureauthenticated) in `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index c468ff7..473d88b 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -20,6 +20,7 @@ defmodule AuthedApp.Router do
   end

   pipeline :user_required do
+    plug Guardian.Plug.EnsureAuthenticated, handler: AuthedApp.GuardianErrorHandler
   end

   pipeline :admin_required do
```

And we put our handler in `web/auth/guardian_error_handler.ex`

```elixir
defmodule AuthedApp.GuardianErrorHandler do
  import AuthedApp.Router.Helpers
  import Phoenix.Controller

  def unauthenticated(conn, _params) do
    conn
    |> put_flash(:error, "You must be signed in to access this page.")
    |> redirect(to: session_path(conn, :new))
  end
end
```

And extend the `admin_required` pipeline by calling a new auth plug
from `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index 7884e29..ef7f7d0 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -24,6 +24,7 @@ defmodule AuthedApp.Router do
   end

   pipeline :admin_required do
+    plug AuthedApp.CheckAdmin
   end

   scope "/", AuthedApp do
```

defined the plug in `web/auth/check_admin.ex`

```elixir
defmodule AuthedApp.CheckAdmin do
  import Phoenix.Controller
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    current_user = Guardian.Plug.current_resource(conn)
    if current_user.is_admin do
      conn
    else
      conn
      |> put_status(:not_found)
      |> render(AuthedApp.ErrorView, "404.html")
      |> halt
    end
  end
end
```

Now a logged in user trying to access `/admin/users` will get a 404
not found, and a non-logged in user will get a 404.


**TODO: currently admin fails since it's AuthedApp.Admin.UserController, remove ", Admin" from router.ex**

**TODO: go back and also add a /users shortcut for admins to bottom of page**

## Seed

Add the admin seed in `priv/repo/seeds.exs`. This file already exists,
so we add the following at the end.

```elixir
alias AuthedApp.Repo
alias AuthedApp.User

admin_params = %{name: "Admin User",
                 email: "admin@example.com",
                 password: "default password",
                 is_admin: true}

unless Repo.get_by(User, email: admin_params[:email]) do
  User.registration_changeset(%User{}, admin_params)
  |> Repo.insert!
end
```

# Ex Machina Tests

**TODO: add `ex_machina`, plus test all the login/auth paths.

# JSON API

**TODO: add json endpoints for registration, login, logout, news, info and user listing for admins.**
