"""
KeyStead Server – serwer synchronizacji (Zero-Knowledge).

Serwer przechowuje WYŁĄCZNIE zaszyfrowane pliki sejfu (.vault) wraz z historią wersji.
Nigdy nie otrzymuje hasła głównego ani klucza – odszyfrowanie odbywa się tylko w aplikacji klienta.
"""

SERVER_VERSION = "1.2.1"
API_PREFIX = "/api/v1"
