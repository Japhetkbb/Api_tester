from rest_framework.views import APIView
from .serializer import *
from rest_framework.response import Response
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404
from .models import Product
from django.db import connection
from django.contrib.auth.models import User


class SafeProductSearchView(APIView):

    """
    Cette API est conçue pour tester la vulnérabilité à une injection SQL.
    Grâce à l'utilisation de l'ORM Django, elle est protégée contre ce type d'attaque.
    Aucune requête brute n'est utilisée : les entrées sont automatiquement échappées,
    rendant les injections SQL inefficaces.
    """

    def get(self, request):
        code = request.query_params.get('code', None)
        if code is None:
            return Response({"message": "Le paramètre 'code' est requis."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            product = Product.objects.get(code=code)
        except Product.DoesNotExist:
            return Response({"message": "Produit non trouvé."}, status=status.HTTP_404_NOT_FOUND)
        product_data = {
            "code": product.code,
            "name": product.name,
            "description": product.description,
            "price": str(product.price),
            "creator": product.creator.username,
            "created_at": product.created_at,
            "updated_at": product.updated_at,
        }
        return Response(product_data, status=status.HTTP_200_OK)


class UnsafeProductSearchView(APIView):

    """
    Cette API est volontairement conçue de manière non sécurisée à des fins pédagogiques.
    Elle construit dynamiquement une requête SQL en injectant directement la valeur du paramètre `code`
    dans la chaîne SQL, sans échappement ni paramétrage.
    """

    def get(self, request):
        code = request.query_params.get('code', None)
        if code is None:
            return Response({"error": "Le paramètre 'code' est requis."}, status=status.HTTP_400_BAD_REQUEST)
        query = f"SELECT * FROM api_product WHERE code = '{code}'"
        with connection.cursor() as cursor:
            cursor.execute(query)
            row = cursor.fetchone()
        if row is None:
            return Response({"error": "Produit non trouvé."}, status=status.HTTP_404_NOT_FOUND)
        product_data = {
            "code": row[0],
            "name": row[1],
            "description": row[2],
            "price": str(row[3]),
            "creator": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        }
        return Response(product_data, status=status.HTTP_200_OK)

class SafeUserProfileView(APIView):
    """
    Cette API est sécurisée.
    Elle nécessite une authentification pour accéder aux données des utilisateurs.
    Protège contre les failles de type "Broken Authentication".
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        data = []

        for user in users:
            data.append({
                "username": user.username,
                "email": user.email,
                "is_staff": user.is_staff
            })

        return Response(status=status.HTTP_200_OK)
    
class UnsafeUserProfileView(APIView):
    """
    Cette API expose des données utilisateur sans exiger d’authentification.
    Elle est vulnérable à une "Broken Authentication".
    """

    def get(self, request):
        users = User.objects.all()
        data = []

        for user in users:
            data.append({
                "username": user.username,
                "email": user.email,
                "is_staff": user.is_staff
            })

        return Response(data, status=status.HTTP_200_OK)



class SafeUserDetailView(APIView):
    """
    API sécurisée contre l'IDOR.
    Seul l'utilisateur authentifié peut accéder à ses propres données.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        if request.user.pk != pk:
            return Response(status=status.HTTP_403_FORBIDDEN)

        user = request.user
        data = {
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff
        }
        return Response(data, status=status.HTTP_200_OK)

class UnsafeUserDetailView(APIView):
    """
    Cette API est vulnérable à l'IDOR.
    Elle permet à n'importe quel utilisateur de consulter les données d’un autre utilisateur en modifiant l’ID dans l’URL.
    Aucun contrôle d’autorisation n’est effectué.
    """
    
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        data = {
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff
        }
        return Response(data, status=status.HTTP_200_OK)
    
    
class SensitiveDataView(APIView):

    """
    Cette vue retourne intentionnellement des informations sensibles (clés API, mots de passe, tokens, etc.)
    à des fins de démonstration ou de test.
    """

    def get(self, request):
        sensitive_data = {
            "secret_key": "abc123XYZ",
            "api_password": "supersecretpassword", ""
            'token': "lkdojklsldklsd65656sjdhdsd",
            "private_info": {
                "ssn": "123-45-6789",
                "address": "1234 Private St.",
            }
        }
        return Response(sensitive_data)


class DivideErrorHandledView(APIView):
    """
    Cette API illustre une bonne pratique en matière de gestion des erreurs.
    Elle simule une division par zéro, mais intercepte l'exception ZeroDivisionError
    pour renvoyer une réponse propre avec un code 400 (Bad Request).
    Cela permet d'éviter une interruption du service côté serveur.
    """
    def get(self, request):
        try:
            result = 1 / 0
        except ZeroDivisionError:
            return Response({'message': 'Division par zéro gérée'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'result': result})


class DivideErrorUnhandledView(APIView):
    """
    Cette API est un exemple de mauvaise configuration ou de mauvaise gestion des erreurs.
    Elle effectue une division par zéro sans intercepter l’exception,
    ce qui provoque une erreur serveur 500.
    Cela démontre un risque courant dans les applications mal protégées.
    """
    def get(self, request):
        result = 1 / 0
        return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class AdminUserListView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def get(self, request):
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ProductList(APIView):
    
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(creator=request.user)
            return Response({'detail': 'Produit créé avec succès.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

