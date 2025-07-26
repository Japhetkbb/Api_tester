import secrets
import string

def generate_secure_token(length=32):
    """Génère un token aléatoire sécurisé"""
    alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))