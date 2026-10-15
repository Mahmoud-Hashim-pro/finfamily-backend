import os

# Enforce isolated, ephemeral in-memory test configuration across all pytest executions
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-ci-secret-key-at-least-32-bytes-secure"
os.environ["GOOGLE_CLIENT_ID"] = "100000000000-dummyclientidforci.apps.googleusercontent.com"
os.environ["APP_VERSION"] = "1.1.0"
os.environ["APP_BUILD_NUMBER"] = "8"
