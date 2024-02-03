from django.urls import path
from . import views

app_name = "myapp"

urlpatterns = [
    path("", views.Home, name="home"),
    path("signup/", views.UserSignup, name="signup"),
    path("create-user/", views.UserSignupView.as_view(), name="create-user"),
    path("activate/<uidb64>/<token>/", views.activate, name="activate"),
    path("login/", views.LoginUser, name="login"),
    path("auth-user/", views.UserLoginView.as_view(), name="auth-user"),
    path("logout/", views.LogoutUser, name="logout"),
    path("upload/", views.UploadFile, name="upload"),
    path('upload-file/', views.FileUploadView.as_view(), name='upload-file'),
    path('file-list/', views.FileListView.as_view(), name='file-list'),
    path('generate-download-token/<int:file_id>/',views.DownloadTokenGenerateView.as_view(), name='generate-download-token'),
    path('download/<int:file_id>/<str:token>/',views.FileDownloadView.as_view(), name='file-download'),
    
]
