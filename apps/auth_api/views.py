from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import UserSerializer, RegisterSerializer
from .models import Profile

# profile view


class UserProfile(ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = UserSerializer


# register view


class UserRegister(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
