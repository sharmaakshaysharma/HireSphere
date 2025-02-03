from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer
from django.contrib.auth import authenticate
from .models import User

class RegisterUser(APIView):    
    def post(self, request):       
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():           
            serializer.save()
            return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class LoginUser(APIView):  
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')        
        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)      
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)        
        hashed_password = User.hash_password(password, user.salt)
        if hashed_password == user.password:            
            refresh = RefreshToken.for_user(user)
            refresh["id"]=user.id
            refresh["email"]=user.email
            refresh["firtsname"] = user.firstname
            refresh["lastname"] = user.last_name
            refresh["role"] = user.role.name
            refresh["country"] = user.country.name
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)