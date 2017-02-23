# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     AuthedApp.Repo.insert!(%AuthedApp.SomeModel{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.
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
