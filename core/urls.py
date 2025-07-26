from django.urls import path
from .views import *


urlpatterns = [
    path('', api_tester, name='api-tester'),
    path('test/sql-injection/', test_sql_injection, name='test_sql_injection'),
    path('test/broken-auth/', test_broken_auth, name='test_broken_auth'),
    path('test/idor/', test_idor, name='test_idor'),
    path('test/data-exposure/', test_data_exposure, name='test_data_exposure'),
    path('test/misconfiguration/', test_misconfiguration, name='test_misconfiguration'),
    path('test/auth-flaws/', test_auth_flaws, name='test_auth_flaws'),
    path('test/function-auth/', test_function_auth, name='test_function_auth'),
]
