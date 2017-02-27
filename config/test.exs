use Mix.Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :authed_app, AuthedApp.Endpoint,
  http: [port: 4001],
  server: false

# Print only warnings and errors during test
config :logger, level: :warn

# Configure your database
config :authed_app, AuthedApp.Repo,
  adapter: Ecto.Adapters.Postgres,
  username: "postgres",
  password: "postgres",
  database: "authed_app_test",
  hostname: "localhost",
  pool: Ecto.Adapters.SQL.Sandbox

config :guardian, Guardian,
 issuer: "AuthedApp.#{Mix.env}",
 ttl: {30, :days},
 verify_issuer: true,
 serializer: AuthedApp.GuardianSerializer,
 secret_key: %{"k" => "ZXZIgc4ZiRAEeCWwKaI9wKHJ3qC4wjLGltWjWrwrrlk", "kty" => "oct"}
