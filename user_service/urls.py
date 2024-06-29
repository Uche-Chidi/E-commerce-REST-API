from django.urls import path
from .views import RegisterUser, CustomAuthToken, UserProfile

urlpatterns = [
    path('register/', RegisterUser.as_view(), name='register'),
    path('login/', CustomAuthToken.as_view(), name='login'),
    path('profile/<str:username>/', UserProfile.as_view(), name='profile'),
]
