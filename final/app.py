import os
import datetime
import sqlite3

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///project.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show all info about (site?)"""
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)


    return render_template("forum.html", username=username)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get(
            "confirmation"
        ):  # add function to confirm the password
            return apology("must confirm password", 400)

        elif request.form.get("password") != request.form.get(
            "confirmation"
        ):  # check for conformation
            return apology("password dont confirmed", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 0:  # check if username already taken
            return apology("Username is taken, choose another one", 400)

        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 404)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 404)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 404)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Allows the user to change their password"""

    user_id = session["user_id"]

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        current_password = db.execute("SELECT hash FROM users WHERE id = ?", user_id)

        # Check for valid user input
        if not old_password:
            return apology("Please enter your Old Password!")
        elif not check_password_hash(current_password[0]["hash"], request.form.get("old_password")):
            return apology("Incorrect password!")
        elif not new_password:
            return apology("Please enter a New Password!")
        elif not confirmation:
            return apology("Please confirm your New Password!")
        elif new_password != confirmation:
            return apology("Passwords must match!")

        hash = generate_password_hash(new_password)

        # Insert new password into db
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, user_id)
        return redirect("/")

    else:
        return render_template("password.html")



@app.route("/fieldreg", methods=["GET", "POST"])
@login_required
def fieldreg():

    """register your own field"""
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("field_name"):
            return apology("must provide Field name")
        user_id = session["user_id"]

        field = request.form.get("field_name")

        n = 150
        p2o5 = 80
        k2o = 220


        db.execute("INSERT INTO fields (user_id, Fieldname, n, p2o5, k2o) VALUES (?, ?, ?, ?, ?)", user_id, field, n, p2o5, k2o)

        flash("Field register")

    return render_template("fieldreg.html")


@app.route("/yourfields")
@login_required
def yourfields():

    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    Fields = db.execute("SELECT * FROM fields WHERE user_id = ?", user_id)

    return render_template("yourfields.html", Fields=Fields, username=username)






@app.route("/calculatef", methods=["POST"])
@login_required
def calculatef():
    if request.method == "POST":
        Fields_id = request.form.get("Fields_id")
        user_id = session["user_id"]

        app.logger.info(Fields_id)
        #id = db.execute("SELECT id FROM Fields WHERE id = ?", Fields_id)
        DataField1 = db.execute("SELECT * FROM Fields WHERE id = ?", Fields_id)
        Fields = DataField1[0]

        grains = db.execute("SELECT * FROM grains")

        return render_template("calculate.html", Fields=Fields, grains=grains)


@app.route("/calculateresult", methods=["POST",])
@login_required
def calculateresult():
    if request.method == "POST":
        grown_id = request.form.get("Grain_id")
        user_id = session["user_id"]
        grown_n = int(db.execute("SELECT n FROM grains WHERE id = ?", grown_id))
        grown_p2o5 = int(db.execute("SELECT p2o5 FROM grainsWHERE id = ?", grown_id))
        grown_k2o = int(db.execute("SELECT k2o FROM grainsWHERE id = ?", grown_id))


        field_name = request.form.get("Field_name")

        field_id = db.execute("SELECT id FROM Fields WHERE Fieldname = ?", field_name)

        field_n = int(db.execute("SELECT n FROM fields WHERE id = ?", field_id))
        field_p2o5 = int(db.execute("SELECT n FROM fields WHERE id = ?", field_id))
        field_k2o = int(db.execute("SELECT n FROM fields WHERE id = ?", field_id))


        n = field_n - grown_n
        p2o5 = field_p2o5 - grown_p2o5
        k2o = field_k2o - grown_k2o

        if n > 100 and p2o5>70 and k2o>200:

            flash("Your field is not depleted, and can grow any grown from offered on the site")

            return("yourfields.html")

        elif n > 20 and p2o5 < 10 and k2o > 100:

            flash("Your field is ready to grow wheat and rice. There is not enough nitrogen and phosphorus in the soil for corn and sugar beets")

            return("yourfields.html")

        elif n < 10 and p2o5 < 10 and k2o > 80:

            flash("The reserves of nitrogen and phosphorus in your field are almost depleted, since corn consumes a lot of these substances. It is recommended to skip one growing season to avoid poor harvest")

            return("yourfields.html")
        elif n < 10 and p2o5 < 10 and k2o > 100:
            flash("The reserves of nitrogen and phosphorus in your field are almost depleted, since sugar beet consumes a lot of these substances. It is recommended to skip one growing season to avoid poor harvest")

            return("forum.html")

@app.route("/forum", methods=["GET", "POST"])
@login_required
def forum():
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    messages = db.execute("SELECT * FROM messages")


    return render_template("forum.html", messages=messages)

@app.route("/forum_r", methods=["GET", "POST"])
@login_required
def forum_reply():
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    messages = db.execute("SELECT * FROM messages WHERE reciver = ?", username)

    return render_template("forum.html", messages=messages)

@app.route("/send", methods=["GET", "POST"])
@login_required
def send():
    """Send a message to other user"""
    if request.method == "GET":

        user_id = session["user_id"]
        sender = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]

        return render_template("send.html", sender=sender)

    else:
        sender = request.form.get("sender")

        title = request.form.get("title")
        text = request.form.get("text")

        if not sender or not title or not text:
            #or not reciver
            return apology("Please fill all columns")
        db.execute("INSERT INTO messages (sender,  title, text) VALUES (?, ?, ?)", sender, title, text)

        return redirect("/forum")


@app.route("/topic", methods=["POST"])
@login_required
def topic():
    if request.method == "POST":
        messages_id = request.form.get("messages_id")
        id = db.execute("SELECT id FROM messages WHERE id = ?", messages_id)
        topic_text1 = db.execute("SELECT * FROM messages WHERE id = ?", messages_id)
        reply_text = topic_text1[0]
        return render_template("topic.html", topic_text=reply_text, id = id)

@app.route("/reply", methods=["POST"])
@login_required
def reply():
    if request.method == "POST":
        topic_id = request.form.get("topic_text_id")
        topic_text1 = db.execute("SELECT * FROM messages WHERE id = ?", topic_id)
        reply_text = topic_text1[0]
        return render_template("reply.html", reply_text=reply_text)



@app.route("/sendreply", methods=["GET", "POST"])
@login_required
def sendreply():
    """Send a message to other user"""
    if request.method == "GET":

        user_id = session["user_id"]
        sender = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]

        return render_template("reply.html", sender=sender)

    else:
        sender = request.form.get("sender")
        reciver = request.form.get("reciver")
        title = request.form.get("title")
        text = request.form.get("text")

        if not sender or not reciver or not title or not text:
            return apology("Please fill all columns")
        db.execute("INSERT INTO messages (sender, reciver, title, text) VALUES (?, ?, ?, ?)", sender, reciver, title, text)

        return redirect("/forum")

@app.route("/answers", methods=["GET", "POST"])
@login_required
def answers():
    user_id = session["user_id"]
    reciver = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]["username"]
    messages = db.execute("SELECT * FROM messages WHERE reciver = ?", reciver)


    return render_template("answers.html", messages=messages)
