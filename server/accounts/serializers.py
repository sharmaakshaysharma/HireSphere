from rest_framework import serializers
from .models import User, Role, Country
import os
from django.core.exceptions import ValidationError
import re
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id', 'name', 'created_at', 'updated_at']
class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = ['id', 'name', 'code']
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)  
    class Meta:
        model = User
        fields = ['id', 'firstname', 'lastname', 'email', 'password', 'role', 'country', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at']
    
    def validate_password(self, value):        
        if len(value) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        if not re.search(r"\d", value):  
            raise ValidationError("Password must contain at least one digit.")
        if not re.search(r"[A-Za-z]", value): 
            raise ValidationError("Password must contain at least one letter.")
        return value
    
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.salt = os.urandom(16)
            instance.password = User.hash_password(password, instance.salt)
        instance.save()
        return instance