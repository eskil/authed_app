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

  def with_encrypted_password(user) do
    %{user | password_hash: Comeonin.Bcrypt.hashpwsalt(user.password)}
  end

  def make_admin(user) do
    %{user | is_admin: true}
  end
end
