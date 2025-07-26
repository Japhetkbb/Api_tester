from .models import Product
from rest_framework import serializers
from django.contrib.auth.models import User

class ProductSerializer(serializers.ModelSerializer):
    creator_name = serializers.CharField(source='creator.username', read_only=True)
    
    
    class Meta:
        model = Product
        fields = ['code', 'name', 'description', 'price', 'creator', 'creator_name', 'created_at', 'updated_at']
        read_only_fields = ['creator', 'created_at', 'updated_at']
        
    def get_creator_name(self, obj):
        return obj.creator.username
        
    def to_representation(self, instance):
        dict_data = super().to_representation(instance)
        dict_data['creator'] = dict_data.pop('creator_name')
        return dict_data


class ProductPriceUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ['price']
        
        
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'is_staff']
