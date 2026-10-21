# Test cases for shieldpipe.yml, run with: semgrep --test .semgrep/
# This file is intentionally insecure and is excluded from every scanner.
import logging

import jwt
from fastapi import FastAPI
from sqlalchemy import text

logger = logging.getLogger(__name__)


def audit(event, **fields):
    pass


def sql_cases(db, name, user_id):
    # ruleid: sql-built-from-string
    db.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
    # ruleid: sql-built-from-string
    db.execute(text("SELECT * FROM users WHERE id = %s" % user_id))
    # ruleid: sql-built-from-string
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")
    # ruleid: sql-built-from-string
    db.execute("DELETE FROM users WHERE id = {}".format(user_id))
    # ok: sql-built-from-string
    db.execute(text("SELECT * FROM users WHERE name = :name").bindparams(name=name))
    # ok: sql-built-from-string
    db.execute(text("SELECT 1"))


def jwt_cases(token, key):
    # ruleid: jwt-decode-without-fixed-algorithms
    jwt.decode(token, key)
    # ok: jwt-decode-without-fixed-algorithms
    jwt.decode(token, key, algorithms=["HS256"])
    # ruleid: jwt-signature-verification-disabled
    jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": False})


def logging_cases(user, password, access_token, request_id):
    # ruleid: secret-written-to-logs
    logger.info("login attempt %s %s", user, password)
    # ruleid: secret-written-to-logs
    audit("auth.login", token=access_token)
    # ok: secret-written-to-logs
    logger.info("request %s", request_id)
    # ok: secret-written-to-logs
    audit("auth.login", actor=user)


# ruleid: fastapi-debug-enabled
debug_app = FastAPI(debug=True)
# ok: fastapi-debug-enabled
prod_app = FastAPI()
