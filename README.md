# Simple E-commerce Store REST API

This project demonstrates a simple e-commerce store REST API that handles user authentication, product management, store management, and category management.


- [Features](#features)
- [Getting Started](#getting-started)
- [Folder Structure](#folder-structure)
- [Technologies Used](#technologies-used)
- [Usage](#usage)
- [Contributing](#contributing)


## Features

- User authentication (sign up, login, profile) using Token Authentication
- CRUD operations for stores (only authenticated users)
- CRUD operations for product categories (only authenticated users)
- CRUD operations for products (only authenticated users)
- Endpoints to list all products, categories, and products within a category
- Endpoint to search for products by name and category


## Getting Started

### Prerequisites

Make sure you have the following installed on your local development environment:

- Python 3.8+
- Django 3.0+
- Django REST Framework


## Installation

1. Clone the repository
    ```bash
    git clone https://github.com/Uche-Chidi/E-commerce-REST-API.git

2. Navigate to the project directory:
    ```bash
    cd ecommerce-rest-api

3. Create and activate a virtual environment:
    ```bash
    python -m venv venv

    On MacOS/ Linux;
    source venv/bin/activate


    On Windows; 
    `venv\Scripts\activate`

4. Install the required dependencies;
    ```bash
    pip install django djangorestframework

5. Apply database migrations;
    ```bash
    python manage.py migrate

6. Run the server;
    ```bash
    python manage.py runserver

## Folder Structure

ecommerce/
│
├── ecommerce/
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── user_services/
│   ├── migrations/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── serializers.py
│   ├── tests.py
│   ├── urls.py
│   └── views.py
│
├── store_services/
│   ├── migrations/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── serializers.py
│   ├── tests.py
│   ├── urls.py
│   └── views.py
│
├── manage.py
└── README.md

# Technologies Used

1. Backend Framework: Django
2. API Framework: Django REST Framework
3. Database: SQLite (default, can be changed to
4. PostgreSQL, MySQL, etc.)
5. Authentication: Token Authentication
6. Search: Django Filters

# Usage

## API Endpoints

### User Authentication
- POST /api/users/signup/ - User sign-up
- POST /api/users/login/ - User login
- GET /api/users/profile/ - User profile
### Store Management
- POST /api/store/ - Create store
- PUT /api/store/{id}/ - Update store
- DELETE /api/store/{id}/ - Delete store

### Product Category Management
- POST /api/categories/ - Create product category
- PUT /api/categories/{id}/ - Update product category
- DELETE /api/categories/{id}/ - Delete product category
### Product Management
- POST /api/products/ - Add product
- PUT /api/products/{id}/ - Update product
- DELETE /api/products/{id}/ - Delete product

### Product Retrieval
- GET /api/products/ - List all products
- GET /api/categories/ - List all categories
- GET /api/categories/{id}/products/ - List products in a category
- GET /api/products/search/?name={name}&category={category} - Search products by name and category


# Contributing

## How to Contribute

1. Fork the repository
2. Create a new branch (git checkout -b feature-branch)
3. Make your changes
4. Commit your changes (git commit -m 'Add new feature')
5. Push to the branch (git push origin feature-branch)
6. Open a Pull Request

## Guidelines
- Ensure the code is well-documented
- Write tests for new features
- Follow the existing code style and structure










