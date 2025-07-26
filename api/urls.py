from django.urls import path
from .views import *
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    # Point d'entrée pour l'authentification par jeton
    path("api-auth/", obtain_auth_token, name="api-auth"),
    # Point d'entrée sécurisé à une injection SQL
    path(
        "safe-product-search/",
        SafeProductSearchView.as_view(),
        name="safe-product-search",
    ),
    # Point d'entrée vulnérable à une injection SQL
    path(
        "un-safe-product-search/",
        UnsafeProductSearchView.as_view(),
        name="un-safe-product-search",
    ),
    # Point d'entrée sécurisé à une authentification casée
    # Point d'entréé sécurisé à une test d'authentification interrompue
    path("safe-user-list/", SafeUserProfileView.as_view(), name="safe-user-list"),
    #  Point d'entrée vulnérable à une authentification casée
    path(
        "un-safe-user-list/", UnsafeUserProfileView.as_view(), name="un-safe-user-list"
    ),
    # Point d'entrée sécurisé à l'idor
    path(
        "safe-user-detail/<int:pk>/",
        SafeUserDetailView.as_view(),
        name="safe-user-detail",
    ),
    # Point d'entrée vulnérable à l'idor
    path(
        "un-safe-user-detail/<int:pk>/",
        UnsafeUserDetailView.as_view(),
        name="un-safe-user-detail",
    ),
    # Point d'entrée vulnérable au test d'exposition des données sensibles
    path("sensitive-data/", SensitiveDataView.as_view(), name="sensitive-data"),
    # Point d'entrée sécurisé au test de mauvaise configuration
    path(
        "divide-error-handled/",
        DivideErrorHandledView.as_view(),
        name="divide-error-handled",
    ),
    # Point d'entrée vulnérable au test de mauvaise configuration
    path(
        "divide-error-unhandled/",
        DivideErrorUnhandledView.as_view(),
        name="divide-error-unhandled",
    ),
    # Point d'entré sécurisé au test d'autorisation au niveau des fonctions
    path("admin/user-list/", AdminUserListView.as_view(), name="admin-user-list"),
    # Point d'entrée pour API product
    path("products/", ProductList.as_view(), name="product-list"),
]
