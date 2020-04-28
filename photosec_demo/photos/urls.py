from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('createuser/', views.create_user, name='create_user'),
    path('logout/', views.logout_view, name='logout'),
    path('qrcode/', views.qr_code, name="qr_code"),
    path('photoupload/<int:user>/<str:token>', views.PhotoUploadView.as_view()),
    path('files/', views.file_list, name="file_list"),
    path('ajax/retrievephotos/', views.photos_retrieve, name="photos_retrieve"),
]