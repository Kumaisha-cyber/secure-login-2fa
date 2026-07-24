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

    otp_secret = db.Column(
        db.String(32),
        nullable=True
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

        otp_secret = pyotp.random_base32()

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            otp_secret=otp_secret
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

        session["pending_user_id"] = user.id

        return redirect(
            url_for("verify_2fa")
        )

    return "Invalid username or password!"


@app.route("/dashboard")
def dashboard():

    if "username" not in session:

        return redirect(
            url_for("home")
        )

    return render_template(
        "dashboard.html",
        username=session["username"]
    )
@app.route(
    "/verify-2fa",
    methods=["GET", "POST"]
)
def verify_2fa():

    if "pending_user_id" not in session:

        return redirect(
            url_for("home")
        )

    user = db.session.get(
        User,
        session["pending_user_id"]
    )

    if not user:

        return "User not found!"

    if request.method == "POST":

        otp = request.form["otp"]

        totp = pyotp.TOTP(
            user.otp_secret
        )

        if totp.verify(otp):

            session["username"] = user.username

            session.pop(
                "pending_user_id",
                None
            )

            return redirect(
                url_for("dashboard")
            )

        return "Invalid OTP!"

    return render_template(
        "verify_2fa.html"
    )

@app.route("/logout")
def logout():

    session.pop(
        "username",
        None
    )

    return redirect(
        url_for("home")
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )
