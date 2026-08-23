from flask import Flask, session

app = Flask(__name__)


def current_user_id() -> int:
    return session["user_id"]
