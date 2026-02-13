from django.urls import path, include
from .views import MFASetupView, MFAVerifyView, LoginView, TestAuthView, MFALoginVerifyView

urlpatterns = [
    path("login/",LoginView.as_view(),name='login'),
    path("mfa/setup/",MFASetupView.as_view(),name='mfa-setup'),
    path("mfa/verify/",MFAVerifyView.as_view(),name='mfa-verify'),
    path("test/",TestAuthView.as_view(),name='test'),
    path("mfa/login-verify/",MFALoginVerifyView.as_view(),name="login-verify"),
]
