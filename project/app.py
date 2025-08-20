from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config["SECRET_KEY"] = "secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite3"

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


def role_required(role):
    """
    Only allow routes for specific roles

    Args:
        role (str): The role that is required to allow access.
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Abort if not the role
            if current_user.role != role:
                abort(403)
            return f(*args, **kwargs)

        return wrapped

    return decorator


# Dashboard protected route, must be logged in to access
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


# Admin route, only admins can access
@app.route("/admin")
@login_required
@role_required("admin")
def admin_page():
    return render_template("admin.html", user=current_user)


# Logout the user route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Registers a new user
    """
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])
        role = request.form["role"]

        user = User(username=username, password=password, role=role)

        db.session.add(user)
        db.session.commit()

        flash("Registered successfully. Please login.")
        # On successfull registration send to login form
        return redirect(url_for("login"))

    # Otherwise, send to the form to register
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login route

    Returns:
        str: The login.html template
    """
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        # Check if password entered matches the stored hashed password, log themm in if so.
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            # Send to dashboard if successful login
            return redirect(url_for("dashboard"))
        else:
            flash("invalid credentials!")
    # send back to login if invalid
    return render_template("login.html")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
