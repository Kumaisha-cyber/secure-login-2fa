from flask import Flask

app = Flask(__name__)


@app.route("/")
def home():
    return "Secure Login System with 2FA"


if __name__ == "__main__":
    app.run(debug=True)
