import requests


def sql_injection(url, param, token=None):
    payload = "' OR '1'='1"
    test_url = f"{url}?{param}={payload}"

    headers = {}
    if token:
        headers["Authorization"] = f"Token {token}"

    result = {
        "test_type": "Injection SQL",
        "url": test_url,
        "param": param,
        "token": token,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
    }

    try:
        response = requests.get(test_url, headers=headers, timeout=10)
        result["status_code"] = response.status_code

        try:
            data = response.json()
        except ValueError:
            data = None

        if response.status_code == 200:
            if data:
                result.update(
                    {
                        "is_vulnerable": True,
                        "message": "La requête a retourné des données - possible vulnérabilité.",
                    }
                )
            else:
                result.update(
                    {
                        "is_vulnerable": False,
                        "message": "Réponse 200 mais sans données - vulnérabilité peu probable.",
                    }
                )
        elif response.status_code in (400, 401, 403, 404):
            result.update(
                {
                    "is_vulnerable": False,
                    "message": "Le serveur a rejeté la requête ou la ressource est introuvable.",
                }
            )
        elif response.status_code == 500:
            result.update(
                {
                    "is_vulnerable": True,
                    "message": "Erreur serveur (500) - possible injection SQL non gérée.",
                }
            )
        else:
            result.update(
                {
                    "is_vulnerable": False,
                    "message": f"Réponse inattendue du serveur (code {response.status_code}).",
                }
            )

    except requests.exceptions.Timeout:
        result.update(
            {
                "status_code": 408,
                "is_vulnerable": False,
                "message": "Délai d'attente dépassé lors de la requête.",
            }
        )
    except requests.exceptions.ConnectionError:
        result.update(
            {
                "status_code": 0,
                "is_vulnerable": False,
                "message": "Erreur de connexion au serveur.",
            }
        )
    except requests.exceptions.RequestException as e:
        result.update(
            {
                "status_code": 0,
                "is_vulnerable": False,
                "message": f"Erreur de requête imprévue : {str(e)}",
            }
        )

    return result


def broken_authentication(url: str):
    result = {
        "test_type": "Authentification cassée",
        "url": url,
        "param": None,
        "token": None,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
    }

    try:
        response = requests.get(url)
        result["status_code"] = response.status_code

        if response.status_code == 401:
            result["message"] = (
                "Accès refusé sans authentification. Comportement attendu."
            )
        elif response.status_code == 200:
            result["is_vulnerable"] = True
            result["message"] = (
                "Accès autorisé sans authentification. Possible faille d’authentification cassée."
            )
        else:
            result["message"] = f"Statut inattendu reçu : {response.status_code}"

    except Exception as e:
        result["message"] = f"Erreur lors de la requête : {str(e)}"

    return result


def idor(url: str, token: str):

    headers = {"Authorization": f"Token {token}"}
    response = requests.get(url, headers=headers)

    result = {
        "test_type": "Référence directe non sécurisée (IDOR)",
        "url": url,
        "token": token,
        "status_code": response.status_code,
        "is_vulnerable": False,
        "message": None,
    }

    if response.status_code == 200:
        result["is_vulnerable"] = True
        result["message"] = (
            "Potentiellement vulnérable à l’IDOR : données accessibles sans autorisation spécifique."
        )
    elif response.status_code == 403:
        result["message"] = (
            "Accès interdit : protection contre IDOR en place (403 Forbidden)."
        )
    elif response.status_code == 404:
        result["message"] = (
            "Ressource non trouvée (404) – ID invalide ou bien protégée."
        )
    else:
        result["message"] = f"Statut inattendu : {response.status_code}."

    return result


def sensitive_data_exposure(url: str):

    result = {
        "test_type": "Exposition de données sensibles",
        "url": url,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
        "exposed_keywords": [],
    }

    try:
        response = requests.get(url)
        result["status_code"] = response.status_code
        content_lower = response.text.lower()
        sensitive_terms = [
            "password",
            "secret",
            "token",
            "api_password",
            "private_info",
        ]

        for term in sensitive_terms:
            if term in content_lower:
                result["is_vulnerable"] = True
                result["exposed_keywords"].append(term)

        if result["is_vulnerable"]:
            result["message"] = (
                "Données sensibles potentiellement exposées : "
                + ", ".join(result["exposed_keywords"])
            )
        else:
            result["message"] = "Aucune donnée sensible détectée dans la réponse."
    except Exception as e:
        result["message"] = f"Erreur lors de la requête : {str(e)}"

    return result


def misconfiguration(url: str):
    result = {
        "test_type": "Mauvaise configuration du serveur",
        "url": url,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
    }

    try:
        response = requests.get(url)
        result["status_code"] = response.status_code

        if response.status_code >= 500:
            result["is_vulnerable"] = True
            result["message"] = f"Mauvaise configuration détectée."
        else:
            result["message"] = f"Aucune erreur serveur détectée."

    except Exception as e:
        result["message"] = f"Erreur lors de la requête : {str(e)}"

    return result


def interrupted_authentication(url: str, token: str):
    result = {
        "test_type": "Authentification interrompue",
        "url": url,
        "token": token,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
    }

    headers = {"Authorization": f"Token {token}"}

    try:
        response = requests.get(url, headers=headers)
        result["status_code"] = response.status_code

        if response.status_code in [401, 403]:
            result["message"] = "Accès refusé."
        elif response.status_code == 200:
            result["is_vulnerable"] = True
            result["message"] = (
                "Problème potentiel : accès autorisé avec un mauvais jeton."
            )
        else:
            result["message"] = f"Réponse inattendue : {response.status_code}"
    except Exception as e:
        result["message"] = f"Erreur lors de la requête : {str(e)}"

    return result


def level_authorization(url: str, token: str):
    headers = {"Authorization": f"Token {token}"}
    result = {
        "test_type": "Autorisation de niveau de fonction",
        "url": url,
        "token": token,
        "status_code": None,
        "is_vulnerable": False,
        "message": None,
        "response_preview": None,
    }

    try:
        response = requests.get(url, headers=headers)
        result["status_code"] = response.status_code

        if response.status_code == 200:
            result["is_vulnerable"] = True
            result["message"] = "Un utilisateur non autorisé a accédé à une ressource protégée !"
        elif response.status_code in (401, 403):
            result["message"] = "Accès refusé - restriction d'accès correctement appliquée."
        else:
            result["message"] = f"Réponse inattendue : {response.status_code}"
    except Exception as e:
        result["message"] = f"Erreur lors de la requête : {str(e)}"

    return result

