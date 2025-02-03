from django.db import models
import hashlib
import os


class Role(models.Model):
    name = models.CharField(max_length=20, db_index=True, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
class Country(models.Model):
    name = models.CharField(max_length=100, unique=True, null=False, blank=False)
    code = models.CharField(max_length=3, unique=True, null=False, blank=False)  

    def __str__(self):
        return self.name


class User(models.Model):
    firstname = models.CharField(max_length=50, db_index=True, null=False, blank=False)
    last_name = models.CharField(max_length=50, db_index=True, null=False, blank=False)
    email = models.EmailField(max_length=50, db_index=True, unique=True, null=False, blank=False)
    password = models.CharField(max_length=128, null=False, blank=False)
    salt = models.BinaryField(max_length=16, null=False, blank=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    country=models.ForeignKey(Country, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    @staticmethod
    def hash_password(password, salt):
        if isinstance(salt, memoryview):
            salt = salt.tobytes()
        return hashlib.sha512(salt + password.encode('utf-8')).hexdigest()

    def save(self, *args, **kwargs):
        if self._state.adding:  
            self.salt = os.urandom(16)
            self.password = User.hash_password(self.password, self.salt)
        super(User, self).save(*args, **kwargs)

    @classmethod
    def create_user(cls, firstname, lastname, email, password, role):
        salt = os.urandom(16)
        password_hash = cls.hash_password(password, salt)
        user = cls(
            first_name=firstname,
            last_name=lastname,
            email=email,
            password=password_hash,
            salt=salt,
            role=role
        )
        user.save()
        return user
    
    def __str__(self):
        return self.firstname 