import os

def run_command(cmd):
    # Rule: python.lang.security.audit.eval-usage
    eval(cmd)

def connect_db():
    # Rule: generic.secrets.gitleaks
    password = "super_secret_password_123"
    print(f"Connecting with {password}")
