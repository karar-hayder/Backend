from django.urls import path

from . import views

app_name = "users"

urlpatterns = [
    path("signup/", views.RegisterView.as_view(), name="signup"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("refresh/", views.RefreshView.as_view(), name="refresh"),
    path("refresh/token/", views.RefreshTokenIssueView.as_view(), name="refresh-token"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("user/", views.CurrentUserView.as_view(), name="current_user"),
    path("profile/edit/", views.EditProfileView.as_view(), name="edit_profile"),
    path("profile/delete/", views.RemoveAccountView.as_view(), name="remove_account"),
]
