from django.shortcuts import render
from .utils import *
from .scanner import *


def api_tester(request):
    return render(request, 'core/api-tester.html')


def test_sql_injection(request):
    result = {}
    if request.method == 'POST':
        param = request.POST.get('param')
        url = request.POST.get('url')
        token = request.POST.get('token', None)  # Optionnel

        result = sql_injection(url, param, token)
        print(result)

    return render(request, 'core/api-tester.html', {
        'active_test': 'sql_injection',
        'result':result
            
    })


def test_broken_auth(request):
    result = {}
    if request.method == 'POST':
        url = request.POST.get('url')
        
        result = broken_authentication(url)

    return render(request, 'core/api-tester.html', {
        'active_test': 'broken_auth',
        'result':result,
    })


def test_idor(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        token = request.POST.get('token')

        result = idor(url, token)

    return render(request, 'core/api-tester.html', {
        'active_test': 'idor',
        'result':result,
    })


def test_data_exposure(request):
    if request.method == 'POST':
        url = request.POST.get('url')

        result = sensitive_data_exposure(url)
    return render(request, 'core/api-tester.html', {
        'active_test': 'data_exposure',
        'result':result,
    })


def test_misconfiguration(request):
    if request.method == 'POST':
        url = request.POST.get('url')

        result = misconfiguration(url)

    return render(request, 'core/api-tester.html', {
        'active_test': 'misconfiguration',
        'result':result,
    })


def test_auth_flaws(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        token = generate_secure_token()

        result = interrupted_authentication(url, token)

    return render(request, 'core/api-tester.html', {
            'active_test': 'auth_flaws',
            'result':result,
        })


def test_function_auth(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        token = request.POST.get('token')

        result = level_authorization(url, token)
       
    return render(request, 'core/api-tester.html', {
            'active_test': 'function_auth',
            'result':result,
            
        })
