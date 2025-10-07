from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from models import db, User, TokenBlocklist
from flasgger import swag_from

auth_bp = Blueprint("auth", __name__)

def role_required(role):
    """
    Simple decorator to check user role.
    Usage: @jwt_required() then call role_required inside endpoint.
    (or wrap this logic in a custom decorator if you prefer)
    """
    def wrapper_check(user: User):
        return user and user.role == role

    return wrapper_check

@auth_bp.route("/signup", methods=["POST"])
@swag_from({
    'tags': ['Auth'],
    'parameters': [
        {'name': 'body', 'in': 'body', 'schema': {
            'type': 'object',
            'properties': {
                'username': {'type': 'string'},
                'email': {'type': 'string'},
                'password': {'type': 'string'},
                'role': {'type': 'string', 'enum': ['user','admin'], 'default': 'user'}
            },
            'required': ['username','email','password']
        }}
    ],
    'responses': {
        201: {'description': 'User created'},
        400: {'description': 'Missing fields'},
        409: {'description': 'Email already exists'}
    }
})
def signup():
    data = request.get_json() or {}
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")

    if not all([username, email, password]):
        return jsonify({"error": "Missing fields"}), 400

    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify({"error": "User with that email or username already exists"}), 409

    user = User(username=username, email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User created successfully", "user": {"username": username, "email": email, "role": role}}), 201


@auth_bp.route("/login", methods=["POST"])
@swag_from({
    'tags': ['Auth'],
    'parameters': [{'name': 'body', 'in': 'body', 'schema': {
        'type': 'object',
        'properties': {'email': {'type': 'string'}, 'password': {'type': 'string'}},
        'required': ['email','password']
    }}],
    'responses': {200: {'description': 'Tokens issued'}, 401: {'description': 'Invalid creds'}}
})
def login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {"id": user.id, "username": user.username, "email": user.email, "role": user.role}
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
@swag_from({
    'tags': ['Auth'],
    'security': [{'BearerAuth': []}],
    'responses': {200: {'description': 'New access token'}, 401: {'description': 'Revoked or invalid'}}
})
def refresh():
    identity = get_jwt_identity()
    new_access = create_access_token(identity=identity)
    return jsonify({"access_token": new_access}), 200


@auth_bp.route("/logout_access", methods=["DELETE"])
@jwt_required()
def logout_access():
    """
    Revoke access token (blacklist its jti).
    """
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti, type="access"))
    db.session.commit()
    return jsonify({"msg": "Access token revoked"}), 200


@auth_bp.route("/logout_refresh", methods=["DELETE"])
@jwt_required(refresh=True)
def logout_refresh():
    """
    Revoke refresh token (blacklist its jti).
    """
    jti = get_jwt()["jti"]
    db.session.add(TokenBlocklist(jti=jti, type="refresh"))
    db.session.commit()
    return jsonify({"msg": "Refresh token revoked"}), 200


@auth_bp.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404
    return jsonify({"username": user.username, "email": user.email, "role": user.role}), 200


@auth_bp.route("/admin-only", methods=["GET"])
@jwt_required()
def admin_only():
    """
    Example of role-protected endpoint.
    Only works for users with role == 'admin'
    ---
    responses:
      200:
        description: OK
      403:
        description: Forbidden
    """
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"msg": "User not found"}), 404

    if user.role != "admin":
        return jsonify({"msg": "Admin privilege required"}), 403

    return jsonify({"msg": f"Welcome, admin {user.username}!"}), 200
