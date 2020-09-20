import os
import datetime
import sqlite3

#from cs50 import SQL

from sqlite3 import Error
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database -- stores username and password hashes
#db = SQL("sqlite:///projectbear.db")

conn = sqlite3.connect("projectbear.db")

# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():

    # Store the username, password, and confirmation in variables
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    # If the method is get, return the html
    if request.method == "GET":
        return render_template("register.html")
    else:
        # Query database to check if username already exists
        cur0 = conn.cursor()
        selectQuery0 = "SELECT * FROM users WHERE username = '" + username + "'";
        cur0.execute(selectQuery0)
        rows = cur0.fetchall()

        # If there were any results, return an error message
        if len(rows) != 0:
            return apology("Sorry, this username already exists", 403)

        # If the username is not entered, return an error message
        if not username:
            return apology("Must provide username", 403)

        # If the password is not entered, return an error message
        if not password:
            return apology("Must provide password", 403)

        # If the password and the confirmation are different, return an error message
        if password != confirmation:
            return apology("The passwords do not match", 403)

        # Store the user's favorite animal
        favAnimal = request.form.get("fav")

        insertQuery = "INSERT INTO users (username, hash, favAnimal) VALUES ('" + username +"','"+ generate_password_hash(password) + "','Bear')";

        # If the information is valid, add the user to the database
        #db.execute("INSERT INTO users (username, hash, favAnimal) VALUES (:username, :password, :favAnimal)", username=username, password=generate_password_hash(password), favAnimal = "Bear")
        cur = conn.cursor()
        cur.execute(insertQuery)

        # Get the registered user's id to keep track of while they are logged in
        selectQuery = "SELECT * FROM users WHERE username = '" + username + "'";
        #updated = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        cur2 = conn.cursor()
        cur2.execute(selectQuery)
        updated = cur2.fetchall()

        # Remember which user has logged in
        session["user_id"] = updated[0][1]

        # Redirect the user to their homepage if they successfully register
        return redirect("/")

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("You must provide a username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        username=request.form.get("username")
        selectQuery = "SELECT * FROM users WHERE username = '" + username + "'";
        #rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        cur = conn.cursor()
        cur.execute(selectQuery)
        rows = cur.fetchall()

        print(rows)
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0][1]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/")
@login_required
def index():
    # Store the user_in in a variable
    user_id = session["user_id"]

    # Returnt the homepage
    return render_template("index.html")

# DONATE/JOIN FOUNDATIONS
@app.route("/donate")
@login_required
def help():
    # Store user_id
    user_id = session["user_id"]

    # Return the help page
    return render_template("help.html")

# LEARN MORE - abt their fav animal
@app.route("/learn")
@login_required
def learn():
    # Return the bear information page
    return render_template("bear.html")


# Game
@app.route("/game")
@login_required
def game():
    # Return the game
    return render_template("PolarRun.html")


# LOGOUT OF THE WEB APPLICATION
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")



