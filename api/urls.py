from django.urls import path
from .auth_views import google_auth_start, google_auth_callback
from .import views

urlpatterns = [
    path('',views.home,name='home'),
    path("auth/google/start/", google_auth_start, name="google-auth-start"),
    path("auth/google/callback/", google_auth_callback, name="google-auth-callback"),
]


"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""