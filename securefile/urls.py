from django.urls import path
from . import views

urlpatterns = [
    path('',views.index,name='index'),
    path('register/',views.register,name='register'),
    path('signin/', views.signin, name='signin'),
    path('signout/', views.signout, name = 'signout'),
    path('dashboard/<str:username>/', views.dashboard, name='dashboard'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('success/',views.success,name='success'),
]
