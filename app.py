from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import pyotp

app = Flask(__name__)

app.secret_key = "change-this-secret-key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(200),
        nullable=False
    )


with app.app_context():
    db.create_all()


@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form["username"]

        email = request.form["email"]

        password = request.form["password"]

        confirm_password = request.form[
            "confirm_password"
        ]

        if password != confirm_password:

            return "Passwords do not match!"

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)

        db.session.commit()

        return "Account created successfully!"

    return render_template(
        "register.html"
    )


@app.route(
    "/login",
    methods=["POST"]
)
def login():

    username = request.form["username"]

    password = request.form["password"]

    user = User.query.filter_by(
        username=username
    ).first()

    if user and bcrypt.check_password_hash(
        user.password,
        password
    ):

        session["username"] = username

        return redirect(
            url_for(
                "dashboard"
            )
        )

    return "Invalid username or password!"


@app.route("/dashboard")
def dashboard():

    @app.route("/logout")
def logout():

    session.pop(
        "username",
        None
    )

    return redirect(
        url_for("home")
    )

    if "username" not in session:

        return redirect(
            url_for("home")
        )

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )
