from django.urls import path
from . import  views
urlpatterns = [
    path('index/', views.get_data),
    path('register/', views.register),
    path('login/', views.login),
    path('logout/', views.logout),
    path('admin/', views.get_all_data),
    path('upload/', views.upload),
    path('export/', views.export),

]