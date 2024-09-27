#!/usr/bin/env python3
""" Flask App
"""

from flask import Flask, jsonify, redirect, request, abort
import flask
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """ POST /users
    Register a new user
    """
    email = flask.request.form.get("email")
    password = flask.request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
        return flask.jsonify({"email": user.email,
                              "message": "user created"}), 200
    except ValueError:
        return flask.jsonify({"message": "email already registered"}), 400


@app.route("/", methods=["GET"], strict_slashes=False)
def index() -> str:
    """ GET /
    Return:
      - message
    """
    return flask.jsonify({"message": "Bienvenue"})


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """ Log in """
    email = request.form.get('email')
    password = request.form.get('password')
    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({'email': email, 'message': 'logged in'})
    response.set_cookie('session_id', session_id)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """ Log out """
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile() -> str:
    """ GET /profile
    Return:
      - empty JSON
      - 403 if the user is not authenticated
    """
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token() -> str:
    """ POST /reset_password
    Return:
      - JSON response with reset token
      - 403 if the email is not registered
    """
    try:
        email = request.form.get('email')
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token}), 200
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password() -> str:
    """ PUT /reset_password
    Return:
      - empty JSON
      - 403 if the email is not registered
    """
    try:
        email = request.form.get('email')
        token = request.form.get('reset_token')
        password = request.form.get('new_password')
        AUTH.update_password(token, password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
