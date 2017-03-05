defmodule AuthedApp.Test.Factory do
  use ExMachina.Ecto, repo: AuthedApp.Repo

  def user_factory do
    %AuthedApp.User{
      name: sequence("User Name"),
      email: sequence(:email, &"email-#{&1}@example.com"),
      password: "test_password_1",
      password_hash: "$2b$12$tx.U0eAdCXl0P.48qZyvqehXybAfSMO8ULnbhmzbwmJoI58LuIx9G",
      is_admin: false
    }
  end

  def make_admin(user) do
    %{user | is_admin: true}
  end
end
