from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class Store(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, related_name='stores', on_delete=models.CASCADE)

class Category(models.Model):
    name = models.CharField(max_length=255)
    store = models.ForeignKey(Store, related_name='categories', on_delete=models.CASCADE)

class Products(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    category = models.ForeignKey(Category, related_name='product', on_delete=models.CASCADE)
    price = models.DecimalField(decimal_places=2, max_digits=20 )