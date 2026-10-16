"""
KeyStead Server – serwer synchronizacji (Zero-Knowledge).

Serwer przechowuje WYŁĄCZNIE zaszyfrowane pliki sejfu (.vault) wraz z historią wersji.
Nigdy nie otrzymuje hasła głównego ani klucza – odszyfrowanie odbywa się tylko w aplikacji klienta.
"""

SERVER_VERSION = "2.0.0"
API_PREFIX = "/api/v1"

# Wersjonowanie produktu: pierwsze dwie liczby wspólne dla serwera i aplikacji (nowe funkcje – razem),
# ostatnia osobno (poprawki). Aplikacja X.Y.* współpracuje z serwerem X.Y.* (i nowszym).
PRODUCT_NAME = "KeyStead"
AUTHOR = "Łukasz Kubieniec"
AUTHOR_GITHUB = "https://github.com/facior"
SERVER_REPOSITORY_URL = "https://github.com/facior/KeyStead-Manager"
APP_REPOSITORY_URL = "https://github.com/facior/KeyStead"
COPYRIGHT = "© 2026 Łukasz Kubieniec. Wszelkie prawa zastrzeżone."


def product_line(version: str) -> str:
    """„2.0” z „2.0.3” – linia produktu, w obrębie której serwer i aplikacja są zgodne."""
    return ".".join(version.split(".")[:2])
