from django.urls import path
from .views import (
    StoreCreateView,StoreListView, StoreDetailView,
    CategoryCreateView, CategoryDetailView,
    ProductCreateView, ProductDetailView, ProductListView,
    ProductsByCategoryView, ProductSearchView
)

urlpatterns = [
    path('stores/', StoreListView.as_view(), name='store-list'),
    path('stores/create/', StoreCreateView.as_view(), name='store-create'),
    path('stores/<int:pk>/', StoreDetailView.as_view(), name='store-detail'),
    path('categories/', CategoryCreateView.as_view(), name='category-create'),
    path('categories/<int:pk>/', CategoryDetailView.as_view(), name='category-detail'),
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/create/', ProductCreateView.as_view(), name='product-create'),
    path('products/<int:pk>/', ProductDetailView.as_view(), name='product-detail'),
    path('categories/<int:category_id>/products/', ProductsByCategoryView.as_view(), name='products-by-category'),
    path('search/', ProductSearchView.as_view(), name='product-search'),
]