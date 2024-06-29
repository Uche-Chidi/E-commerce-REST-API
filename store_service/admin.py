from django.contrib import admin
from .models import Store, Category, Products

# Register your models here.
admin.site.register(Store)
admin.site.register(Category)
admin.site.register(Products)