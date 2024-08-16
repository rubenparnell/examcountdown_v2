from flask import render_template
from flask_login import login_required, current_user
from app import app

@app.route("/")
def home():
    return render_template("home.html", current_user=current_user)


@app.route("/profile")
def profile():
    return render_template("profile.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/logout")
def logout():
    return render_template("logout.html")