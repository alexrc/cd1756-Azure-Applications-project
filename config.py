import os

class Config(object):
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key"

    BLOB_ACCOUNT = os.environ.get("BLOB_ACCOUNT")
    BLOB_STORAGE_KEY = os.environ.get("BLOB_STORAGE_KEY")
    BLOB_CONTAINER = os.environ.get("BLOB_CONTAINER")
    BLOB_CONNECTION_STRING = os.environ.get("BLOB_CONNECTION_STRING")

    SQL_SERVER = os.environ.get("SQL_SERVER")
    SQL_DATABASE = os.environ.get("SQL_DATABASE")
    SQL_USER_NAME = os.environ.get("SQL_USER_NAME")
    SQL_PASSWORD = os.environ.get("SQL_PASSWORD")

    CLIENT_ID = os.environ.get("CLIENT_ID")
    CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
    TENANT_ID = os.environ.get("TENANT_ID")

    AUTHORITY = "https://login.microsoftonline.com/common"
    REDIRECT_PATH = "/getAToken"
    SCOPE = ["User.Read"]