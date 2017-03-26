# User and Admin auth with Ex Machina tests and JSON API

I'm going to go through [this excellent blog post by Andrei
Chernykh](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#.i4w5d87sl)
to setup a phoenix app with user/admin auth.

Then I'll extend the project by adding JSON API endpoints and
unit-tests using Ex Machina.

## Let's begin

Since the first large part is going through Andrei Chernykh's
post, I'll keep this bit short and less detailed than his
excellent post. For the sake of forcing myself to actually write
all the things, I'm renaming the app from `simple_auth` to
`authed_app` and skipping the post models.

I recommend reading his blog post, and if you follow that, you
can basically skip to [the next chapter](#ex-machina-tests).

### Start a phoenix project

Create a new blank project and do your initial commit.

```bash
mix phoenix.new authed_app
mix ecto.create
cd authed_app
git init .
git add .
git commit -m "Initial commit."
```

### Add user model

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
@@ -4,12 +4,16 @@
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
+
   @doc """
   Builds a changeset based on the `struct` and `params`.
   """
@@ -17,5 +21,6 @@
     struct
     |> cast(params, @required_fields ++ @optional_fields)
     |> validate_required(@required_fields)
+    |> validate_format(:email, ~r/@/)
   end
```

Run migration to create the db and users table.

```bash
mix ecto.migrate
```

Since we modified the schema to "validate" the email in some minimal
fashion, the generated unit test needs a tweak too.

```diff
diff --git a/test/models/user_test.exs b/test/models/user_test.exs
index 52c3140..4706dbb 100644
--- a/test/models/user_test.exs
+++ b/test/models/user_test.exs
@@ -3,7 +3,11 @@ defmodule AuthedApp.UserTest do

   alias AuthedApp.User

-  @valid_attrs %{email: "some content", is_admin: true, name: "some content", password_hash: "some c
+  @valid_attrs %{
+    email: "test@email.com",
+    is_admin: true,
+    name: "some content",
+    password_hash: "some content"}
   @invalid_attrs %{}

   test "changeset with valid attributes" do
```

### User controller

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

### User registration form

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

### Registration

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
@@ -23,4 +23,31 @@
     |> validate_required(@required_fields)
     |> validate_format(:email, ~r/@/)
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
+    |> validate_required([:password])
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
`create/2` method use the `registration_changeset/2`

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


## Session controller

Sessions are managed by `new/2` which is the login form, `create/2` which
is a login form submit and `delete/2` which is the logout.

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
$ curl --request GET --cookie-jar ~/.cookiejar --verbose  localhost:4000/sessions/new
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
$ curl --header "x-csrf-token: eVJ4HyFrRScdUA01SHVuaAEXbDI0JgAALgOHsS1qs14Vp8+P2d9CYw==" \
  --request POST --form 'session[email]=test1@example.com' --form 'session[password]=PASSWORD' \
  --cookie ~/.cookiejar --verbose  localhost:4000/sessions
```

This will end with a crash since SessionController's `create/2` isn't implemented yet:
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

### Implement login with Guardian

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
`config/prod.exs` with a production specific key (preferably not in the file but via env variables or such). To generate the key,
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

Hook up SessionController's `create/2` in
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

### Refactoring

We're now
[here in the blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#6687).

We'll refactor SessionController's `login/2` and `logout/1` to enable
logging in when registering. Move `login/2` and `logout/1` to
`web/auth/auth.ex` and add `login_by_email_and_password/3`.

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



### Session specific pages

We are now [now here in the
blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#b9df),
and we'll start to deviate slightly. I won't be adding the posts
models etc, only the signed in/not signed in/admin distinction.

  * A `/public` page available to all.
  * A `/private` page only available to signed in users.
  * A `/users` page that lists all users, only available to admins.

These will be available from the front page, where we'll replace the
"Resources" and "Help" lists with a single "Pages" list. And this list
will only show the links available given the current session.

We already have a UserController that can list the users for the
`/user` endpoint. We'll add two controllers for `/public` and `/private`.

In `web/controllers/public_controller.ex` (note, you could use `mix
phoenix.gen.html` for a lot of this, but keeping this explicit).

```elixir
defmodule AuthedApp.PublicController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
```

it's corresponding view module in `/web/views/public_view.ex`

```elixir
defmodule AuthedApp.PublicView do
  use AuthedApp.Web, :view
end
```

and the template in `web/templates/public/index.html.eex`

```html
<h2>Public</h2>
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
+    get "/public", PublicController, :index
   end

   # Other scopes may use custom stacks.
```

Do the same for an PrivateController, add it to `web/controllers/private_controller.ex`

```elixir
defmodule AuthedApp.PrivateController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
```

it's corresponding view module in `/web/views/private_view.ex`

```elixir
defmodule AuthedApp.PrivateView do
  use AuthedApp.Web, :view
end
```

and the template in `web/templates/private/index.html.eex`

```html
<h2>Private</h2>
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
     get "/public", PublicController, :index
+    get "/private", PrivateController, :index
   end

   # Other scopes may use custom stacks.
```

Add the `/users` index endpoint to list users, first we add the
handler to UserController in `web/controllers/user_controller.ex`

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
     get "/public", PublicController, :index
     get "/private", PrivateController, :index
```

Now we all the endpoints but not authorisation checks.


## Authorisation checks on pages

We're still [here in the
blog](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#b9df),
and now resume adding the three kinds of authorisation.

We first rearrange our routes so we can use specific pipelines and
also put some endpoints behind a `/admin` prefix which is nice.

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
    public_path  GET     /public        AuthedApp.PublicController :index
   private_path  GET     /private       AuthedApp.PrivateController :index
```

We add two pipelines (`admin_required` and `user_required`) and
rearrange routes in `web/router.ex` so they're in the right
pipelines. Note they're nested.

```diff
diff --git a/web/router.ex b/web/router.ex
index ea883ee..7325ed5 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -19,19 +19,32 @@ defmodule AuthedApp.Router do
     plug AuthedApp.CurrentUser
   end

-  pipeline :with_session do
-    plug Guardian.Plug.VerifySession
-    plug Guardian.Plug.LoadResource
+  pipeline :user_required do
+  end
+
+  pipeline :admin_required do
   end

   scope "/", AuthedApp do
     pipe_through [:browser, :with_session]

+    # Public routes.
     get "/", PageController, :index
-    resources "/users", UserController, only: [:show, :new, :create, :index]
+    resources "/users", UserController, only: [:show, :new, :create]
     resources "/sessions", SessionController, only: [:new, :create, :delete]
     get "/public", PublicController, :index
-    get "/private", PrivateController, :index
+
+    scope "/" do
+      # Login required.
+      pipe_through [:user_required]
+      get "/private", PrivateController, :index
+    end
+
+    scope "/admin", Admin, as: :admin do
+      # Admin account required.
+      pipe_through [:admin_required]
+      resources "/users", UserController, only: [:index]
+    end
   end

   # Other scopes may use custom stacks.
```

I choose to move the `/admin` endpoint out into their own scope
outside the `user_required` pipeline. This is specifically to keep the
error handled different between the two, namely I want errors in
`user_required` to redirect to login, but errors for `admin_required`
to look like 404s.

The routes now look like

```bash
$ mix phoenix.routes
Compiling 17 files (.ex)
      page_path  GET     /              AuthedApp.PageController :index
      user_path  GET     /users/new     AuthedApp.UserController :new
      user_path  GET     /users/:id     AuthedApp.UserController :show
      user_path  POST    /users         AuthedApp.UserController :create
   session_path  GET     /sessions/new  AuthedApp.SessionController :new
   session_path  POST    /sessions      AuthedApp.SessionController :create
   session_path  DELETE  /sessions/:id  AuthedApp.SessionController :delete
    public_path  GET     /public        AuthedApp.PublicController :index
   private_path  GET     /private       AuthedApp.PrivateController :index
admin_user_path  GET     /admin/users   AuthedApp.Admin.UserController :index
```

Or in a diff

```diff
--- extra-files-for-readme/routes	2017-02-26 22:17:03.000000000 -0800
+++ extra-files-for-readme/routes-new	2017-02-26 22:16:19.000000000 -0800
@@ -1,5 +1,4 @@
       page_path  GET     /              AuthedApp.PageController :index
-      user_path  GET     /users         AuthedApp.UserController :index
       user_path  GET     /users/new     AuthedApp.UserController :new
       user_path  GET     /users/:id     AuthedApp.UserController :show
       user_path  POST    /users         AuthedApp.UserController :create
@@ -8,3 +7,4 @@
    session_path  DELETE  /sessions/:id  AuthedApp.SessionController :delete
     public_path  GET     /public        AuthedApp.PublicController :index
    private_path  GET     /private       AuthedApp.PrivateController :index
+admin_user_path  GET     /admin/users   AuthedApp.Admin.UserController :index
```

Remove the `index/2` handler from `UserController` and move it into a
new `Admin.UserController` in `web/admin/user_controller.ex`

```elixir
defmodule AuthedApp.Admin.UserController do
  use AuthedApp.Web, :controller

  alias AuthedApp.User

  def index(conn, _params) do
    render(conn, "index.html", users: Repo.all(User))
  end
end
```

```diff
diff --git a/web/controllers/user_controller.ex b/web/controllers/user_controller.ex
index 2719bf7..5b36fa1 100644
--- a/web/controllers/user_controller.ex
+++ b/web/controllers/user_controller.ex
@@ -29,8 +29,4 @@ defmodule AuthedApp.UserController do
         render(conn, "new.html", changeset: changeset)
     end
   end
-
-  def index(conn, _params) do
-    render(conn, "index.html", users: Repo.all(User))
-  end
 end
```

We also need to add a new view in `web/views/admin/user_view.ex`

```elixir
defmodule AuthedApp.Admin.UserView do
  use AuthedApp.Web, :view
end
```

And finally the template in `web/templates/user/index.html.eex` has to
be moved to `web/templates/admin/user.html.eex`

```bash
mkdir -p web/templates/admin/user
git mv web/templates/user/index.html.eex web/templates/admin/user/
```

The user index page will only be available to admin users (after we're
done with the next section). And admin controllers/views will now live
in `web/controllers/admin` and `web/views/admin` respectively, giving
us some structure that could be used for eg. linting rules.



### Implemention authorisation pipelines

#### `user_required`

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

#### `admin_required`

Extend the `admin_required` pipeline by calling a new auth plug
from `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index c0c86a2..06badc1 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -24,6 +24,8 @@ defmodule AuthedApp.Router do
   end

   pipeline :admin_required do
+    plug Guardian.Plug.EnsureAuthenticated, handler: AuthedApp.Admin.GuardianErrorHandler
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

and the admin-specific guarding error handler in `web/auth/admin_guardian_error_handler.ex`

```elixir
defmodule AuthedApp.Admin.GuardianErrorHandler do
  import Phoenix.Controller
  import Plug.Conn

  def unauthenticated(conn, _params) do
    conn
    |> put_status(:not_found)
    |> render(AuthedApp.ErrorView, "404.html")
    |> halt
  end
end
```

Now if you access `/private` without being logged in, you should be
redirected to the login page, and you'll only see the `/private` link on
the home page if you're logged in.

Now a logged in user trying to access `/admin/users` will get a 404
Not Found, and a non-logged in user will get a 404.


I skip the `action/2`
[override](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#cf42)
of a
[controller](https://hexdocs.pm/phoenix/Phoenix.Controller.html#summary)
that Andrei does, since I'm interested in the routing authorisation
aspects. But it's a good trick to know. Likewise we won't get into the
`resources` within `resources` routing part that he does.




### Navigation consolidation

Let's cleanup the links in the headers/footers by moving them into
separate templates.

We want the header to be a `header.html.eex` and the footer to be a
`footer.html.eex`. The purpose is not just to keep the files
small/isolated, but also to allow for different headers/footers for
admins/users with different content.

We'll move the navigation links and "marketing" links into two new
html templates.

In `web/templates/layout/app.html.eex`, replace the sign in/register links with calls
to a new function `navigation_header/1` and a `footer/1` function that we'll define afterwards.

```diff
diff --git a/web/templates/layout/app.html.eex b/web/templates/layout/app.html.eex
index 6e61e12..d8305f2 100644
--- a/web/templates/layout/app.html.eex
+++ b/web/templates/layout/app.html.eex
@@ -14,17 +14,7 @@
   <body>
     <div class="container">
       <header class="header">
-        <nav role="navigation">
-          <ul class="nav nav-pills pull-right">
-            <%= if @current_user do %>
-              <li><%= @current_user.name %> (<%= @current_user.email %>)</li>
-              <li><%= link("Sign out", to: session_path(@conn, :delete, @current_user), method: "delete") %></li>
-            <%= else %>
-              <li><%= link "Register", to: user_path(@conn, :new) %></li>
-              <li><%= link "Sign in", to: session_path(@conn, :new) %></li>
-            <%= end %>
-          </ul>
-        </nav>
+        <%= navigation_header(assigns) %>
         <span class="logo"></span>
       </header>

@@ -35,6 +25,8 @@
         <%= render @view_module, @view_template, assigns %>
       </main>

+      <%= footer(assigns) %>
+
     </div> <!-- /container -->
     <script src="<%= static_path(@conn, "/js/app.js") %>"></script>
   </body>
```

`assigns` is the collection of arguments passed to `render/3`. See
[the phoenix
docs](https://hexdocs.pm/phoenix/Phoenix.View.html#functions) for
more.

Add the two new functions to `web/views/layout_view.ex` since
this is the view module used here.

```diff
diff --git a/web/views/layout_view.ex b/web/views/layout_view.ex
index 8b3cb87..e6d59b5 100644
--- a/web/views/layout_view.ex
+++ b/web/views/layout_view.ex
@@ -1,3 +1,11 @@
 defmodule AuthedApp.LayoutView do
   use AuthedApp.Web, :view
+
+  def navigation_header(assigns) do
+    render("navigation_header.html", assigns)
+  end
+
+  def footer(assigns) do
+    render("footer.html", assigns)
+  end
 end
```

In `web/templates/page/index.html.eex` remove the "marketing" links

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

Put the removed sign in/register template bits in
`web/templates/layout/navigation_header.html.eex`

```html
<nav role="navigation">
  <ul class="nav nav-pills pull-right">
    <%= if @current_user do %>
      <li><%= @current_user.name %>&nbsp;</li>
      <li><%= link("Sign out", to: session_path(@conn, :delete, @current_user), method: "delete") %></li>
    <%= else %>
      <li><%= link "Register", to: user_path(@conn, :new) %></li>
      <li><%= link "Sign in", to: session_path(@conn, :new) %></li>
    <%= end %>
  </ul>
</nav>
```

and in `web/templates/layout/footer.html.eex`, we put the marketing
links, but rewrite them to something more useful, namely the links (private,
public, users) but only visible to the right users.

```html
<div class="col-lg-6">
  <h4>Resources</h4>
  <ul>
    <%= if @current_user do %>
      <li>
        <a href="/private">Private</a>
      </li>
    <%= end %>
    <li>
      <a href="/public">Public</a>
    </li>
  </ul>
</div>

<%= if @current_user && @current_user.is_admin do %>
  <div class="col-lg-6">
    <h4>Admin</h4>
    <ul>
      <li>
        <a href="/admin/users">Users</a>
      </li>
    </ul>
  </div>
<%= end %>
```


** TODO: /users/:id is public to all users**


### Seed

As
[Andrei](https://medium.com/@andreichernykh/phoenix-simple-authentication-authorization-in-step-by-step-tutorial-form-dc93ea350153#46cc)
suggets, add the admin seed in `priv/repo/seeds.exs`. This file
already exists as part of phoenix (see [Seeding
Data](http://www.phoenixframework.org/docs/seeding-data)], so we add
the following at the end.

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

Insert the seeds into your db

```bash
mix run priv/repo/seeds.exs
```

This gives an easy way to create an initial default admin account on
eg. heroku. But be careful with this, since the login and password
will be in your source tree.



## Ex Machina Tests

### Setup

First off, configure guardian in your `config/test.exs`. Follow the
steps as earlier to generate a secret key.

```diff
diff --git a/config/test.exs b/config/test.exs
index 107580c..1488491 100644
--- a/config/test.exs
+++ b/config/test.exs
@@ -17,3 +17,10 @@ config :authed_app, AuthedApp.Repo,
   database: "authed_app_test",
   hostname: "localhost",
   pool: Ecto.Adapters.SQL.Sandbox
+
+config :guardian, Guardian,
+ issuer: "AuthedApp.#{Mix.env}",
+ ttl: {30, :days},
+ verify_issuer: true,
+ serializer: AuthedApp.GuardianSerializer,
+ secret_key: %{"k" => "ZXZIgc4ZiRAEeCWwKaI9wKHJ3qC4wjLGltWjWrwrrlk", "kty" => "oct"}
```



### Start testing

Let's write a test case to ensure that `/private` is only available for
logged in users.

```elixir
defmodule AuthedApp.PrivateControllerTest do
  use AuthedApp.ConnCase

  test "unregistered GET /private redirects to registration", %{conn: conn} do
    conn = get conn, private_path(conn, :index)
    assert redirected_to(conn) == session_path(conn, :new)
  end
end
```

and run it

```bash
$ mix test --trace test/controllers/private_controller_test.exs

AuthedApp.PrivateControllerTest
  * test unregistered GET /private redirects to registration (31.9ms)


Finished in 0.08 seconds
1 test, 0 failures
```

We'll want to extend the test to include registered users, and we'll
eventually want to test `/admin/users` too, so we'll want to test both
non-admin and admin users. This is where [Ex
Machina](https://github.com/thoughtbot/ex_machina) comes in. It's an
excellent library for implementing factories for unit-test
fixtures. Follow [the
instructions](https://hexdocs.pm/ex_machina/readme.html) on how to
install in test-only, ie. don't run the `ex_machina` application in
production.

```diff
diff --git a/mix.exs b/mix.exs
index fa593ef..a688549 100644
--- a/mix.exs
+++ b/mix.exs
@@ -39,7 +39,9 @@ defmodule AuthedApp.Mixfile do
      {:gettext, "~> 0.11"},
      {:cowboy, "~> 1.0"},
      {:comeonin, "~> 2.5"},
-     {:guardian, "~> 0.14"}]
+     {:guardian, "~> 0.14"},
+     {:ex_machina, "~> 1.0", only: :test}
+    ]
   end

   # Aliases are shortcuts or tasks specific to the current project.
```

```diff
diff --git a/test/test_helper.exs b/test/test_helper.exs
index 1439b4e..1d5a6b8 100644
--- a/test/test_helper.exs
+++ b/test/test_helper.exs
@@ -2,3 +2,4 @@ ExUnit.start

 Ecto.Adapters.SQL.Sandbox.mode(AuthedApp.Repo, :manual)

+{:ok, _} = Application.ensure_all_started(:ex_machina)
```

### First factory and test

We'll put our Ex Machina factories in `test/support/factory.ex`, and
initially make a user factory plus a way to make this user admin.

```elixir
defmodule AuthedApp.Test.Factory do
  use ExMachina.Ecto, repo: AuthedApp.Repo

  def user_factory do
    %AuthedApp.User{
      name: sequence("User Name"),
      email: sequence(:email, &"email-#{&1}@example.com"),
      password: sequence("password"),
      is_admin: false
    }
  end

  def make_admin(user) do
    %{user | is_admin: true}
  end
end
```

In `test/controllers/private_controller_test.exs`, we add a `setup/0`
method and a second test to assert that accessing `/private` for a
registered user shows the private page.

```diff
diff --git a/test/controllers/private_controller_test.exs b/test/controllers/private_controller_test.exs
index b3a49e0..3cde983 100644
--- a/test/controllers/private_controller_test.exs
+++ b/test/controllers/private_controller_test.exs
@@ -1,8 +1,33 @@
 defmodule AuthedApp.PrivateControllerTest do
   use AuthedApp.ConnCase

-  test "GET /private as anonymous redirects to registration", %{conn: conn} do
+  import AuthedApp.Test.Factory
+
+  setup do
+    # Get a connection, see https://hexdocs.pm/phoenix/Phoenix.ConnTest.html#build_conn/0.
+    anon_conn = build_conn()
+    # Use AuthedApp.Test.Factory to insert the user created by user_factory/0.
+    user = insert(:user)
+    # Sign in this user and get the signed in connection.
+    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
+    # Return ok plus a map of values test functions can match against.
+    {:ok, %{
+        user: user,
+        anon_conn: anon_conn,
+        user_conn: user_conn
+        }
+    }
+  end
+
+  # Note this test uses anon_conn to test unregistered users.
+  test "GET /private as anonymous redirects to registration", %{anon_conn: conn} do
     conn = get conn, private_path(conn, :index)
     assert redirected_to(conn) == session_path(conn, :new)
   end
+
+  # Note this test uses user_conn to test registered and signed in users.
+  test "GET /private as user", %{user_conn: conn} do
+    conn = get conn, private_path(conn, :index)
+    assert html_response(conn, 200) =~ "Private"
+  end
 end
```

The test suite is now

```bash
$ mix test --trace test/controllers/private_controller_test.exs

AuthedApp.PrivateControllerTest
  * test unregistered GET /private redirects to registration (195.4ms)
  * test registered GET /private  (36.0ms)


Finished in 0.3 seconds
2 tests, 0 failures
```


### Test admin access

Let's add a unit-test for ensuring anonymous and regular users get a
404 Not Found when accessing '/admin/users', but that admins can
access the page. In `test/controllers/admin/user_controller_test.exs`

```elixir
defmodule AuthedApp.Admin.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    anon_conn = build_conn()
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    admin = insert(:user) |> make_admin
    admin_conn = Guardian.Plug.api_sign_in(anon_conn, admin, :token)
    {:ok, %{
        user: user,
        admin: admin,
        anon_conn: anon_conn,
        user_conn: user_conn,
        admin_conn: admin_conn
        }
    }
  end

  test "GET /admin/users as anonymous redirects to registration", %{anon_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as user redirects to registration", %{user_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert conn.status == 404
  end

  test "GET /admin/users as admin", %{admin_conn: conn} do
    conn = get conn, admin_user_path(conn, :index)
    assert html_response(conn, 200) =~ "Users"
  end
end
```

Add tests for `SessionController`, here we'll use `POST` with JSON and
`DELETE` calls. In `test/controllers/session_controller_test.exs`:

```elixir
defmodule AuthedApp.SessionControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  setup do
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(build_conn(), user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
        }
    }
  end

  test "GET /sessions/new", %{conn: conn} do
    conn = get(conn, session_path(conn, :new))
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "POST /sessions/new", %{conn: conn} do
    conn = post(conn, session_path(conn, :create),
                %{"session" => %{"email" => "foo", "password" => "bar"}})
    assert html_response(conn, 200) =~ "Sign in"
  end

  test "DELETE /sessions/:id", %{conn: conn, user: user} do
    conn = delete(conn, session_path(conn, :delete, user.id))
    assert redirected_to(conn) == page_path(conn, :index)
  end
end
```

Add a `test/controllers/user_controller_test.exs` where we test the
various path of user creation etc. in `UserController`.

```elixir
defmodule AuthedApp.UserControllerTest do
  use AuthedApp.ConnCase

  import AuthedApp.Test.Factory

  alias AuthedApp.User

  setup do
    anon_conn = build_conn()
    user = insert(:user)
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        user_conn: user_conn,
        anon_conn: anon_conn
        }
    }
  end

  test "GET /users/new", %{conn: conn} do
    conn = get(conn, user_path(conn, :new))
    assert html_response(conn, 200) =~ "User Registration"
  end

  test "POST /users fails when missing parameters", %{conn: conn} do
    conn = post(conn, user_path(conn, :create),
                %{"user" => %{}})
    assert html_response(conn, 200) =~ "There are some errors"
  end

  test "POST /users", %{conn: conn} do
    conn = post(conn, user_path(conn, :create),
                %{"user" =>
                   %{
                     "email" => "user@email.com",
                     "password" => "password",
                     "name" => "User Name"
                   }
                 })
    user = Repo.get_by(User, email: "user@email.com")
    # Check a id was assigned, a hashed password.
    assert user.id && user.password_hash && !user.password
    assert redirected_to(conn) == user_path(conn, :show, user.id)
  end

  test "GET /users/:id as anonymous", %{anon_conn: conn, user: user} do
    conn = get(conn, user_path(conn, :show, user.id))
    assert html_response(conn, 200) =~ user.name
  end
end
```


### Coverage with ExCoveralls

We'll add [excoveralls](https://github.com/parroty/excoveralls), an
unit-test coverage tool. Like exmachina, it's a `mix.exs` addition.

```diff
diff --git a/mix.exs b/mix.exs
index a688549..aa5f1a1 100644
--- a/mix.exs
+++ b/mix.exs
@@ -10,7 +10,14 @@ defmodule AuthedApp.Mixfile do
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      aliases: aliases(),
-     deps: deps()]
+     deps: deps(),
+     test_coverage: [tool: ExCoveralls],
+     preferred_cli_env: [
+       "coveralls": :test,
+       "coveralls.detail": :test,
+       "coveralls.post": :test,
+       "coveralls.html": :test]
+    ]
   end

   # Configuration for the OTP application.
@@ -40,7 +47,8 @@ defmodule AuthedApp.Mixfile do
      {:cowboy, "~> 1.0"},
      {:comeonin, "~> 2.5"},
      {:guardian, "~> 0.14"},
-     {:ex_machina, "~> 1.0", only: :test}
+     {:ex_machina, "~> 1.0", only: :test},
+     {:excoveralls, "~> 0.6", only: :test}
     ]
   end
```

And get the deps

```bash
mix deps.get
```

ExCoveralls dumps a simple text output when run

```bash
$ mix coveralls.html
.................

Finished in 0.7 seconds
17 tests, 0 failures

Randomized with seed 260773
----------------
COV    FILE                                        LINES RELEVANT   MISSED
 75.0% lib/authed_app.ex                              31        4        1
  0.0% lib/authed_app/endpoint.ex                     42        0        0
  0.0% lib/authed_app/repo.ex                          3        0        0
  0.0% test/support/channel_case.ex                   43        4        4
100.0% test/support/conn_case.ex                      44        4        0
100.0% test/support/factory.ex                        16        3        0
 66.7% test/support/model_case.ex                     65        6        2
100.0% web/auth/admin_guardian_error_handler.ex       11        1        0
 22.2% web/auth/auth.ex                               33        9        7
 80.0% web/auth/check_admin.ex                        18        5        1
 50.0% web/auth/current_user.ex                        9        2        1
100.0% web/auth/guardian_error_handler.ex             10        1        0
100.0% web/auth/guardian_serializer.ex                12        1        0
  0.0% web/channels/user_socket.ex                    37        0        0
100.0% web/controllers/admin/user_controller.ex        9        1        0
100.0% web/controllers/info_controller.ex              7        1        0
100.0% web/controllers/page_controller.ex              7        1        0
  0.0% web/controllers/public_controller.ex            7        1        1
 40.0% web/controllers/session_controller.ex          29        5        3
100.0% web/controllers/user_controller.ex             32        9        0
  0.0% web/gettext.ex                                 24        0        0
100.0% web/models/user.ex                             50        6        0
 80.0% web/router.ex                                  57        5        1
  0.0% web/views/admin/user_view.ex                    3        0        0
 80.0% web/views/error_helpers.ex                     40        5        1
100.0% web/views/error_view.ex                        17        1        0
  0.0% web/views/private_view.ex                          3        0        0
100.0% web/views/layout_view.ex                       11        2        0
  0.0% web/views/page_view.ex                          3        0        0
  0.0% web/views/public_view.ex                        3        0        0
  0.0% web/views/session_view.ex                       3        0        0
  0.0% web/views/user_view.ex                          3        0        0
  0.0% web/web.ex                                     81        1        1
[TOTAL]  70.5%
----------------
Generating report...

$ open cover/excoveralls.html
```

This will open the coverage report in a nice html form. Here you can
easily see two main coverage issues, `PublicController` and
`SessionController create`.

`PublicController` is trivial since there's no functionality and no
access control by `web/router.ex`. So add
`test/controllers/public_controller_test.exs`

```elixir
defmodule AuthedApp.PublicControllerTest do
  use AuthedApp.ConnCase

  test "GET /public", %{conn: conn} do
    conn = get conn, public_path(conn, :index)
    assert html_response(conn, 200) =~ "Public"
  end
end
```

The other missing test is the path in `SessionControllerTest` `create/2`
that actually logs in a user given email and password. So let's extend
`test/controllers/session_controller_test.exs` to test the login path,
using both correct and wrong credentials.

```diff
diff --git a/test/controllers/session_controller_test.exs b/test/controllers/session_controller_test.exs
index 705dd44..c84c67a 100644
--- a/test/controllers/session_controller_test.exs
+++ b/test/controllers/session_controller_test.exs
@@ -5,10 +5,12 @@ defmodule AuthedApp.SessionControllerTest do

   setup do
     user = insert(:user)
-    user_conn = Guardian.Plug.api_sign_in(build_conn(), user, :token)
+    anon_conn = build_conn()
+    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
     {:ok, %{
         user: user,
         user_conn: user_conn,
+        anon_conn: anon_conn
         }
     }
   end
@@ -18,10 +20,32 @@ defmodule AuthedApp.SessionControllerTest do
     assert html_response(conn, 200) =~ "Sign in"
   end

-  test "POST /sessions/new", %{conn: conn} do
+  test "POST /sessions/new with invalid email", %{anon_conn: conn, user: user} do
     conn = post(conn, session_path(conn, :create),
-                %{"session" => %{"email" => "foo", "password" => "bar"}})
-    assert html_response(conn, 200) =~ "Sign in"
+                %{"session" => %{
+                   "email" => "typo" <> user.email,
+                   "password" => user.password
+                 }})
+    assert html_response(conn, 200) =~ "Invalid email or password"
+  end
+
+  test "POST /sessions/new with invalid password", %{anon_conn: conn, user: user} do
+    conn = post(conn, session_path(conn, :create),
+                %{"session" => %{
+                   "email" => user.email,
+                   "password" => "typo" <> user.password
+                 }})
+    assert html_response(conn, 200) =~ "Invalid email or password"
+  end
+
+  test "POST /sessions/new with valid parameters", %{anon_conn: conn, user: user} do
+    conn = post(conn, session_path(conn, :create),
+                %{"session" => %{
+                   "email" => user.email,
+                   "password" => user.password
+                 }})
+    assert redirected_to(conn) == page_path(conn, :index)
+    assert get_flash(conn) == %{"info" => "You're signed in"}
   end

   test "DELETE /sessions/:id", %{conn: conn, user: user} do
```

For this to work, we need to extend the user factory to also store the
hashed password. So in `test/support/factory.ex` to pipe all user
instances through a function that hashes the password.

```diff
diff --git a/test/support/factory.ex b/test/support/factory.ex
index 3911679..33c235f 100644
--- a/test/support/factory.ex
+++ b/test/support/factory.ex
@@ -7,7 +7,11 @@ defmodule AuthedApp.Test.Factory do
       email: sequence(:email, &"email-#{&1}@example.com"),
       password: sequence("password"),
       is_admin: false
-    }
+    } |> encrypt_password
+  end
+
+  def encrypt_password(user) do
+    %{user | password_hash: Comeonin.Bcrypt.hashpwsalt(user.password)}
   end

   def make_admin(user) do
```

The unit test coverage is now 84.6% and it looks like every line of
code we added is now covered.

Turns out that the password hashing is pretty slow, and adding this to
all instances of calling the user factory bumps the test time from <2s
to ~7s on my laptop.

```bash
$ iex -S mix
Erlang/OTP 19 [erts-8.2] [source] [64-bit] [smp:8:8] [async-threads:10] [hipe] [kernel-poll:false] [dtrace]
Interactive Elixir (1.4.1) - press Ctrl+C to exit (type h() ENTER for help)
iex(1)> :timer.tc(fn -> Enum.each(1..10, fn _ -> Comeonin.Bcrypt.hashpwsalt("foo") end) end)
{2997733, :ok}
```

10 calls to hashing takes about 3 seconds.

There's two ways to solve this, either enhance our factories to make
the encrypted password be optional, or make the factory have a fixed
password and store the hashed value directly.

The first option looks like these changes to `test/support/factory.ex`

```diff
diff --git a/test/support/factory.ex b/test/support/factory.ex
index 33c235f..b4d0934 100644
--- a/test/support/factory.ex
+++ b/test/support/factory.ex
@@ -7,10 +7,10 @@ defmodule AuthedApp.Test.Factory do
       email: sequence(:email, &"email-#{&1}@example.com"),
       password: sequence("password"),
       is_admin: false
-    } |> encrypt_password
+    }
   end

-  def encrypt_password(user) do
+  def with_encrypted_password(user) do
     %{user | password_hash: Comeonin.Bcrypt.hashpwsalt(user.password)}
   end
```

and `test/controllers/session_controller_test.exs`

```diff
diff --git a/test/controllers/session_controller_test.exs b/test/controllers/session_controller_test.exs
index c84c67a..9d4a35a 100644
--- a/test/controllers/session_controller_test.exs
+++ b/test/controllers/session_controller_test.exs
@@ -4,7 +4,7 @@ defmodule AuthedApp.SessionControllerTest do
   import AuthedApp.Test.Factory

   setup do
-    user = insert(:user)
+    user = build(:user) |> with_encrypted_password |> insert
     anon_conn = build_conn()
     user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
     {:ok, %{
```

Now the tests are back to ~3s on my laptop.

But if we instead want to simply hardcode the password and hash value
in the fixture, we get the original speed again.

Revert the patch in `test/controllers/session_controller_test.exs`

```diff
diff --git a/test/controllers/session_controller_test.exs b/test/controllers/session_controller_test.exs
index 9d4a35a..c84c67a 100644
--- a/test/controllers/session_controller_test.exs
+++ b/test/controllers/session_controller_test.exs
@@ -4,7 +4,7 @@ defmodule AuthedApp.SessionControllerTest do
   import AuthedApp.Test.Factory

   setup do
-    user = build(:user) |> with_encrypted_password |> insert
+    user = insert(:user)
     anon_conn = build_conn()
     user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
     {:ok, %{
```

Pick a static password for our default user factory, ala `password0`
and generate a hash for it.

```bash
$ iex -S mix
iex(1)> Comeonin.Bcrypt.hashpwsalt("test_password_1")
"$2b$12$tx.U0eAdCXl0P.48qZyvqehXybAfSMO8ULnbhmzbwmJoI58LuIx9G"
```

And fix up `test/support/factory.ex`

```diff
diff --git a/test/support/factory.ex b/test/support/factory.ex
index b4d0934..b1c4ac4 100644
--- a/test/support/factory.ex
+++ b/test/support/factory.ex
@@ -5,15 +5,12 @@ defmodule AuthedApp.Test.Factory do
     %AuthedApp.User{
       name: sequence("User Name"),
       email: sequence(:email, &"email-#{&1}@example.com"),
-      password: sequence("password"),
+      password: "test_password_1",
+      password_hash: "$2b$12$tx.U0eAdCXl0P.48qZyvqehXybAfSMO8ULnbhmzbwmJoI58LuIx9G",
       is_admin: false
     }
   end

-  def with_encrypted_password(user) do
-    %{user | password_hash: Comeonin.Bcrypt.hashpwsalt(user.password)}
-  end
-
   def make_admin(user) do
     %{user | is_admin: true}
   end
```

and the tests are back down to <2s.

Storing static passwords and hashes is reasonable approach in many
situations. I won't got into editorial and begin to talk about fast
unit-tests versus factory induced variety etc.. YMMV and you can
always add separate factories for separate test cases.



## JSON API

For the next step, we'll make JSON API endpoints for the the existing
`/public`, `/private`, `/login`, `/signup`, `/admin/users` HTML
endpoints. It should basically look like

Allow access to public API

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  http://localhost:4000/api/v1/public
...
< HTTP/1.1 200 OK
...
{"public_news":"none"}
```

Disallow access to private API for unauthenticated users

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  http://localhost:4000/api/v1/private
...
< HTTP/1.1 403 Forbidden
...
```

Allow signup with field validation.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  --request POST --data '{"email":"", "password": ""}' \
  http://localhost:4000/api/v1/signup
...
< HTTP/1.1 400 Bad Request
...
{"status":"error", <messages>}
```

And of course handle signup with valid fields.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  --request POST --data '{"email":"user@email.com", "password": "password"}' \
  http://localhost:4000/api/v1/signup
...
< HTTP/1.1 201 Created
< authorization: <jwt token>
< x-expires: <ts>
...
```

A subsequent login should also validate fields.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  --request PUT --data '{"email":"bad email", "password": ""}' \
  http://localhost:4000/api/v1/login
...
< HTTP/1.1 400 Bad Request
...
{"status":"error", <messages>}
```

And successfully login when fields are ok.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  --request PUT --data '{"email":"test1@example.com", "password": "password"}' \
  http://localhost:4000/api/v1/login
...
< HTTP/1.1 200 OK
< authorization: <jwt token>
< x-expires: <ts>
...
```

Allow access to private pages for authenticated users.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" \
  --header "authorization: <jwt token>" \
  localhost:4000/api/v1/private
...
< HTTP/1.1 200 OK
...
{"private_news":"none"}
```

And `/admin/users` should list all users, but only for admin users, non-admin get 401.

### Update routes

We need to add a router session for the JSON api. It's slightly different from the HTML
`:with_session` in that we'll be using the [guardian header
check](https://hexdocs.pm/guardian/Guardian.Plug.VerifyHeader.html)
instead of [the session
check](https://hexdocs.pm/guardian/Guardian.Plug.VerifySession.html)

```diff
diff --git a/web/router.ex b/web/router.ex
index 20bbff7..5572f49 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -19,6 +19,12 @@ defmodule AuthedApp.Router do
     plug AuthedApp.CurrentUser
   end

+  pipeline :with_api_session do
+    plug Guardian.Plug.VerifyHeader
+    plug Guardian.Plug.LoadResource
+    plug AuthedApp.CurrentUser
+  end
+
   pipeline :login_required do
     plug Guardian.Plug.EnsureAuthenticated, handler: AuthedApp.GuardianErrorHandler
   end
```

Add the routes for the endpoints we want to define. We scope them so
the urls are `/api/v1/...` and the route path helpers all look like
`api_v1_..._path/2`. This is one way to version APIs. In `web/router.ex`:

```diff
diff --git a/web/router.ex b/web/router.ex
index 5572f49..fadc35f 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -56,8 +56,20 @@ defmodule AuthedApp.Router do
     end
   end

-  # Other scopes may use custom stacks.
-  # scope "/api", AuthedApp do
-  #   pipe_through :api
-  # end
+  scope "/api", AuthedApp.API, as: :api do
+    pipe_through [:api, :with_api_session]
+    scope "/v1", V1, as: :v1 do
+      post "/signup", SessionController, :signup
+      put "/login", SessionController, :login
+      get "/public", PublicController, :index
+      scope "/" do
+        pipe_through [:login_required]
+        get "/private", PrivateController, :index
+      end
+      scope "/admin", Admin, as: :admin do
+        pipe_through [:admin_required]
+        resources "/users", UserController, only: [:index]
+      end
+    end
+  end
 end
```

There's no `/logout`, since [JWT tokens don't work like that](http://stackoverflow.com/questions/21978658/invalidating-json-web-tokens). The
routes now look like this.

```bash
$ mix phoenix.routes
             page_path  GET     /                    AuthedApp.PageController :index
             user_path  GET     /users/new           AuthedApp.UserController :new
             user_path  GET     /users/:id           AuthedApp.UserController :show
             user_path  POST    /users               AuthedApp.UserController :create
          session_path  GET     /sessions/new        AuthedApp.SessionController :new
          session_path  POST    /sessions            AuthedApp.SessionController :create
          session_path  DELETE  /sessions/:id        AuthedApp.SessionController :delete
           public_path  GET     /public              AuthedApp.PublicController :index
          private_path  GET     /private             AuthedApp.PrivateController :index
       admin_user_path  GET     /admin/users         AuthedApp.Admin.UserController :index
   api_v1_session_path  POST    /api/v1/signup       AuthedApp.API.V1.SessionController :signup
   api_v1_session_path  PUT     /api/v1/login        AuthedApp.API.V1.SessionController :login
    api_v1_public_path  GET     /api/v1/public       AuthedApp.API.V1.PublicController :index
   api_v1_private_path  GET     /api/v1/private      AuthedApp.API.V1.PrivateController :index
api_v1_admin_user_path  GET     /api/v1/admin/users  AuthedApp.API.V1.Admin.UserController :index
```

### Private and public controllers

These are fairly trivial. First add `web/api/v1/controllers/private_controller.ex`

```elixir
defmodule AuthedApp.API.V1.PrivateController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
```

and `web/api/v1/controllers/public_controller.ex`

```elixir
defmodule AuthedApp.API.V1.PublicController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
```

they both need a view class, start with `web/api/v1/views/private_view.ex`

```elixir
defmodule AuthedApp.API.V1.PrivateView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{private_news: news}
  end
end
```

and `web/api/v1/views/public_view.ex`

```elixir
defmodule AuthedApp.API.V1.PublicView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{public_news: news}
  end
end
```

### JSON API authentication

If you now test `/public` and `/private`, we'll see that `/private`
fails because of the auth error handler trying to put a flash
noticication in the response.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" localhost:4000/api/v1/public
...
< HTTP/1.1 200 OK
...
{"public_news":"none"}
```

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" localhost:4000/api/v1/private
...
< HTTP/1.1 500 Internal Server Error
...
```

And on the server side

```
[info] GET /api/v1/private
[info] Sent 500 in 10ms
[error] #PID<0.391.0> running AuthedApp.Endpoint terminated
Server: localhost:4000 (http)
Request: GET /api/v1/private
** (exit) an exception was raised:
    ** (ArgumentError) flash not fetched, call fetch_flash/2
        (phoenix) lib/phoenix/controller.ex:1015: Phoenix.Controller.get_flash/1
        (phoenix) lib/phoenix/controller.ex:1000: Phoenix.Controller.put_flash/3
        (authed_app) web/auth/guardian_error_handler.ex:7: AuthedApp.GuardianErrorHandler.unauthenticated/2
        (authed_app) web/router.ex:28: AuthedApp.Router.login_required/2
        (authed_app) web/router.ex:1: AuthedApp.Router.match_route/4
        (authed_app) web/router.ex:1: AuthedApp.Router.do_call/2
        (authed_app) lib/authed_app/endpoint.ex:1: AuthedApp.Endpoint.phoenix_pipeline/1
        (authed_app) lib/plug/debugger.ex:123: AuthedApp.Endpoint."call (overridable 3)"/2
        (authed_app) lib/authed_app/endpoint.ex:1: AuthedApp.Endpoint.call/2
        (plug) lib/plug/adapters/cowboy/handler.ex:15: Plug.Adapters.Cowboy.Handler.upgrade/4
        (cowboy) /Users/eskil/src/github/eskil/authed_app.api/deps/cowboy/src/cowboy_protocol.erl:442: :cowboy_protocol.execute/4
```

We need to modify our `GuardianErrorHandler` to handle both html and
json. However, turns out that of course guardian supplies a good
[default error handler](https://github.com/ueberauth/guardian/blob/master/lib/guardian/plug/error_handler.ex) that handles JSON and HTML well.

We won't replace our existing `GuardianErrorHandler` since handling
HTML will typically require some tweaking for a good user experience.

But we'll modify the api routes to use `Guardian.Plug.ErrorHandler`
for sessions that require login.

```diff
diff --git a/web/router.ex b/web/router.ex
index 5809eca..c5cc011 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -34,6 +34,15 @@ defmodule AuthedApp.Router do
     plug AuthedApp.CheckAdmin
   end

+  pipeline :api_login_required do
+    plug Guardian.Plug.EnsureAuthenticated, handler: Guardian.Plug.ErrorHandler
+  end
+
+  pipeline :api_admin_required do
+    plug Guardian.Plug.EnsureAuthenticated, handler: Guardian.Plug.ErrorHandler
+    plug AuthedApp.CheckAdmin
+  end
+
   scope "/", AuthedApp do
     pipe_through [:browser, :with_session]

@@ -63,11 +72,11 @@ defmodule AuthedApp.Router do
       put "/login", SessionController, :login
       get "/public", PublicController, :index
       scope "/" do
-        pipe_through [:login_required]
+        pipe_through [:api_login_required]
         get "/private", PrivateController, :index
       end
       scope "/admin", Admin, as: :admin do
-        pipe_through [:admin_required]
+        pipe_through [:api_admin_required]
         resources "/users", UserController, only: [:index]
       end
     end
```

Test it again.

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" localhost:4000/api/v1/private
...
< HTTP/1.1 401 Unauthorized
...
{"errors":["Unauthenticated"]}
```

But let's add unit-tests instead. Add
`test/api/v1/controllers/public_controller_test.exs`, which is fairly
trivial.

```elixir
defmodule AuthedApp.API.V1.PublicControllerTest do
  use AuthedApp.ConnCase

  test "GET /public", %{conn: conn} do
    conn = get conn, api_v1_public_path(conn, :index)
    assert json_response(conn, 200) == %{"public_news" => "none"}
  end
end
```

`API.V1.PrivateControllerTest` reuses some of the prior tests' factory
usage and setup. Note that we set the accept header during setup. In
`test/api/v1/controllers/private_controller_test.exs`


```elixir
defmodule AuthedApp.API.V1.PrivateControllerTest do
  use AuthedApp.ConnCase
  import AuthedApp.Test.Factory

  setup do
    user = insert(:user)
    anon_conn = build_conn()
    |> put_req_header("accept", "application/json")
    user_conn = Guardian.Plug.api_sign_in(anon_conn, user, :token)
    {:ok, %{
        user: user,
        anon_conn: anon_conn,
        user_conn: user_conn
        }
    }
  end

  test "GET /public as anonymous", %{anon_conn: conn} do
    conn = get conn, api_v1_private_path(conn, :index)
    assert json_response(conn, 401) == %{"errors" => ["Unauthenticated"]}
  end

  test "GET /public as user", %{user_conn: conn} do
    conn = get conn, api_v1_private_path(conn, :index)
    assert json_response(conn, 200) == %{"private_news" => "none"}
  end
end
```


### JSON API account creation and login

Now that we can start adding a `AuthedApp.API.V1.SessionController` to
allow registration and login.

We'll go straight to the controller and view, then add the two extra
modules for argument validation and representing validation errors as
json.

In `web/api/v1/controllers/session_controller.ex`, put

```elixir
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
```

Validation of email and password parameters are handled via a schema
defintion, just like we use for our databasemodels. `signup/2` uses
`User.registration_changeset`, but for `login/2`, we want a separate
that purely checks the JSON paramters. Make a schema in
`web/api/v1/models/login_params.ex` that we'll use for the validation.

```elixir
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
    |> validate_format(:email, ~r/@/)
  end
end
```

We need to render the validation errors as dicts to return
json. Changeset validation errors look like

```elixir
[email: {"has invalid format", [validation: :format]},
 password: {"can't be blank", [validation: :required]}]
```

Create `lib/changeset_errors.ex` which is used by
`AuthedApp.API.V1.SessionController`

```elixir
defmodule AuthedApp.Changesets do
  def errors_to_dict(changeset) do
    changeset.errors
    |> Enum.map(fn {k, v} -> %{k => render_message(v)} end)
  end

  defp render_message({message, values}) do
    values
    |> Enum.reduce(message, fn {k, v}, acc ->
      String.replace(acc, "%{#{k}}", to_string(v))
    end)
  end

  defp render_message(message) do
    message
  end
end
```

```bash
$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" --request PUT --data '{"email":"bad email", "password": ""}' http://localhost:4000/api/v1/login
...
< HTTP/1.1 400 Bad Request
...
{"errors":[{"email":"has invalid format"},{"password":"can't be blank"}]}

$ curl --verbose  --header "Content-Type: application/json" --header "Accept: application/json" --request PUT --data '{"email":"test1@example.com", "password": "password"}' http://localhost:4000/api/v1/login
...
< HTTP/1.1 200 OK
...
< authorization: <long jwt token>
< x-expires: <timestamp>
...
{}
```



**TODO: add json endpoints for registration, login, news, private and user listing for admins.**

* done Add /login route
* Add sesion controller plus changes to auth.ex and user_controller
* done Add login params that session controller needs
* done Add changeset_errors
* done Finally session_view
* done curl login and show private works
* unit-tests
* Add /admin/users to routes
  * Add users controller



Add routes for our JSON API in `web/router.ex`

```diff
diff --git a/web/router.ex b/web/router.ex
index 20bbff7..6d2d6ff 100644
--- a/web/router.ex
+++ b/web/router.ex
@@ -50,8 +50,20 @@ defmodule AuthedApp.Router do
     end
   end

-  # Other scopes may use custom stacks.
-  # scope "/api", AuthedApp do
-  #   pipe_through :api
-  # end
+  scope "/api", AuthedApp.API do
+    pipe_through [:api]
+    scope "/v1", V1, as: :v1 do
+      post "/login", SessionController, :login
+      get "/logout", SessionController, :logout
+      get "/public", PublicController, :index
+      scope "/" do
+        pipe_through [:login_required]
+        get "/private", PrivateController, :index
+      end
+      scope "/admin", Admin, as: :admin do
+        pipe_through [:admin_required, :login_required]
+        get "/users", UserController, :index
+      end
+    end
+  end
 end
```


Add public controller to `web/api/controllers/v1/public_controller.ex`

```elixir
defmodule AuthedApp.API.V1.PublicController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
```

and it's view module to `web/api/views/v1/public_view.ex`

```elixir
defmodule AuthedApp.API.V1.PublicView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{public_news: news}
  end
end
```

```bash
$ curl localhost:4000/api/v1/public
{"public_news":"none"}
```

And ditto for the private controller to `web/api/controllers/v1/private_controller.ex`

```elixir
defmodule AuthedApp.API.V1.PrivateController do
  use AuthedApp.Web, :controller

  def index(conn, _params) do
    render(conn, "index.json", news: "none")
  end
end
```

and it's view module to `web/api/views/v1/private_view.ex`

```elixir
defmodule AuthedApp.API.V1.PrivateView do
  use AuthedApp.Web, :view

  def render("index.json", %{news: news}) do
    %{private_news: news}
  end
end
```

```bash
$ curl localhost:4000/api/v1/private
{"private_news":"none"}
```


**TODO:**

* Add /users to routes
  * Add users controller
