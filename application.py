import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, send_from_directory

from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from matplotlib import pyplot as plt

from helpers import login_required

from contextlib import suppress

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

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

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///outWORK.db")

# Homepage route
@app.route("/")
@login_required
def index():


    # get user/routine info from database
    try:
        user = db.execute("""SELECT username FROM users WHERE user_id = :user_id""", user_id=session["user_id"])
        routines = db.execute("""SELECT * FROM routines WHERE user_id = :user_id""", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    # parse username
    username = user[0]["username"]

    # if no routines, display empty homepage
    if not routines:
        routine_flag = False
        return render_template("index.html", username=username, routine_flag=routine_flag)
    else:
        routine_flag = True

    # determine which routines to show and get their exercises
    try:
        routines_with_exercises = db.execute("SELECT DISTINCT routine_id FROM exercises WHERE user_id=:user_id", user_id=session["user_id"])
        exercises = db.execute("SELECT * FROM exercises WHERE user_id = :user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("index.html", username=username, routines=routines, routines_with_exercises=routines_with_exercises, routine_flag=routine_flag, exercises=exercises)

    return render_template("error.html", message="Internal Server Error [index]")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", message="Must Provide Username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html", message="Must Provide Password")

        # Query users table for username
        try:
            rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", message="Invalid Username and/or Password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

    # Something broke
    return render_template("error.html", message="Internal Server Error")



@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        # get username
        username = request.form.get("username")
        if not username:
            return render_template("error.html", message="Invalid Username")

        # username format check
        if len(username) < 1 or not username.isalnum():
            return render_template("error.html", message="Invalid Username")

        # see if username already taken
        check = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        if check:
            return render_template("error.html", message="Username Unavailable")

        # get password
        password = request.form.get("password")
        if not password:
            return render_template("error.html", message="Please Provide a Password")

        # get password confirmation
        confirmation = request.form.get("confirmation")
        if not confirmation:
            return render_template("error.html", message="Must Confirm Password")

        # make sure password and confirmation match
        if password != confirmation:
            return render_template("error.html", message="Passwords Do Not Match")

        # hash password
        hash = generate_password_hash(request.form.get("password"))

        # register user
        try:
            registration = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=username, hash=hash)
        except IOError:
        # if not registration:
            return render_template("error.html", message="Registration Failed")

        session["user_id"] = registration
        return redirect("/")

    else:
        return render_template("register.html")

    return render_template("error.html", message="Internal Server Error")


# route to check if username available
@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # check username was input
    username = request.args.get("username")

    if not username:
        return render_template("error.html", message="Must Provide Username")

    # Guarantee username of at least length 1
    if len(username) > 0:

        # grab username from users table
        try:
            user = db.execute("""SELECT username FROM users WHERE username = :username""", username=username)
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        # if user exists return False (unavilable) else return True (available)
        if user:
            return jsonify(False)
        else:
            return jsonify(True)
    else:
        return jsonify(False)

    # Something broke
    return render_template("error.html", message="Internal System Error")


# route to allow user to change password
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """CHANGE PASSWORD"""

    if request.method == "POST":

        # Get user's current password
        curr_password = request.form.get("curr_password")

        # Check for valid input
        if len(curr_password) < 1:
            return render_template("error.html", message="invalid current password")

        # Get user's new password
        new_password = request.form.get("new_password")

        # Check for valid input
        if len(new_password) < 1:
            return render_template("error.html", message="invalid new password")

        # Get user's confirmation of password
        conf_password = request.form.get("conf_password")

        # Check if new and confirmation match
        if new_password != conf_password:
            return render_template("error.html", message="invalid confirmation")

        # Get current hash for user password
        try:
            user_dict = db.execute("SELECT hash FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        old_hash = user_dict[0]["hash"]

        # Compare old hash with user's current password they gave
        if check_password_hash(old_hash, curr_password):

            # Generate new hash and update users table
            hash = generate_password_hash(new_password)

            try:
                db.execute("""UPDATE users SET hash = :hash WHERE user_id = :user_id""", user_id=session["user_id"], hash=hash)
            except IOError:
                return render_template("error.html", message="Internal Server Error")

            return redirect("/")

        # User's given current password does not match password in users table
        else:
            return render_template("error.html", message="incorrect password")

    # Reached via GET
    else:
        try:
            username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        return render_template("change_password.html", username=username[0]["username"])

    # Something broke
    return render_template("error.html", message="Internal Server Error")

# default route to manage routines
@app.route("/manage_routines", methods=["GET"])
@login_required
def manage_routines():

    # get username and routines
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        routines = db.execute("SELECT routine_name FROM routines WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_routines.html", username=username[0]["username"], routines=routines)

    return render_template("error.html", message="Internal Server Error")


# route to create routine
@app.route("/create_routine", methods=["GET", "POST"])
@login_required
def create_routine():

    if request.method == "POST":

        # get routine name from form
        new_routine = request.form.get("routine_name")
        if not new_routine:
            return render_template("error.html", message="Error [Please select a routine]")

        # insert into routine table
        try:
            db.execute("INSERT INTO routines (routine_name, user_id) VALUES (:routine_name, :user_id)", routine_name=new_routine, user_id=session["user_id"])
            # username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        # send to home page
        return redirect("/")

    # get username for display purposes
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_routines.html", username=username[0]["username"])

    return render_template("error.html", message="Internal Server Error [create_routine]")

@app.route("/delete_routine", methods=["GET", "POST"])
@login_required
def delete_routine():

    if request.method == "POST":

        # get routine name from form
        routine_name = request.form.get("routine_name")
        if not routine_name:
            return render_template("error.html", message="Error [Please select a routine]")

        # parse routine_id, then delete routine and all exercises in that routine
        try:
            routine_id = db.execute("""SELECT routine_id FROM routines
                                WHERE routine_name=:routine_name AND user_id=:user_id""",
                                routine_name=routine_name, user_id=session["user_id"])

            db.execute("""DELETE FROM routines
                        WHERE routine_name=:routine_name AND user_id=:user_id""",
                        routine_name=routine_name, user_id=session["user_id"])

            db.execute("""DELETE FROM exercises
                        WHERE routine_id=:routine_id AND user_id=:user_id""",
                        routine_id=routine_id[0]["routine_id"], user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

    # get routines and username for display purposes
    try:
        routines = db.execute("""SELECT routine_name FROM routines WHERE user_id=:user_id""", user_id=session["user_id"])
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_routines.html", username=username[0]["username"], routines=routines)

    return render_template("error.html", message="Internal Server Error")


# route to add an exercise
@app.route("/add_exercise", methods=["GET", "POST"])
@login_required
def add_exercise():

    if request.method == "POST":

        # get routine_name and exercise_name from form
        routine_name = request.form.get("routine_name")
        exercise_name = request.form.get("exercise_name")
        if not routine_name and exercise_name:
            return render_template("error.html", message="Could not get routine or exercise info")

        # get routine_id
        try:
            routine_id = db.execute("SELECT routine_id FROM routines WHERE routine_name=:routine_name AND user_id=:user_id", routine_name=routine_name, user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        # input exercise into exercises table and update routine to show that it has an exercise
        try:
            db.execute("""INSERT INTO exercises (exercise_name, routine_id, user_id)
                        VALUES (:exercise_name, :routine_id, :user_id)""",
                        exercise_name=exercise_name, routine_id=routine_id[0]["routine_id"], user_id=session["user_id"])

            db.execute("""UPDATE routines SET has_exercises = 1
                        WHERE routine_id=:routine_id AND user_id=:user_id""",
                        routine_id=routine_id[0]["routine_id"], user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

    # grab username, exercises, and routines for display purposes
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        exercises = db.execute("SELECT exercise_name, routine_id FROM exercises WHERE user_id=:user_id", user_id=session["user_id"])
        routines = db.execute("SELECT routine_name, routine_id FROM routines WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_exercises.html", username=username[0]["username"], routines=routines, exercises=exercises)

    return render_template("error.html", message="Internal Server Error [manage_exercises]")


# route to remove exercise
@app.route("/remove_exercise", methods=["GET", "POST"])
@login_required
def remove_exercise():

    if request.method == "POST":

        # get info from form
        routine_id = request.form.get("routine_id")
        exercise_name = request.form.get("exercise_name")

        if not routine_id:
            return render_template("error.html", message="Error [Invalid Routine]")

        if not exercise_name:
            return render_template("error.html", message="Error [Invalid Exercise]")

        # delete exercise from exercises table
        try:
            db.execute("""DELETE FROM exercises
                        WHERE exercise_name=:exercise_name AND routine_id=:routine_id AND user_id=:user_id""",
                        exercise_name=exercise_name, routine_id=routine_id, user_id=session["user_id"])

            # find any exercises that are still attached to that routine
            exercises_in_routine = db.execute("""SELECT * FROM exercises
                                    WHERE routine_id=:routine_id AND user_id=:user_id""",
                                    routine_id=routine_id, user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        # no exercises attached to routine: indicate so in routines table
        if len(exercises_in_routine) < 1:
            try:
                db.execute("""UPDATE routines SET has_exercises = 0
                            WHERE routine_id=:routine_id AND user_id=:user_id""",
                            routine_id=routine_id, user_id=session["user_id"])
            except IOError:
                return render_template("error.html", message="Internal Server Error: Error Updating Routines")

    # get info for display purposes
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        exercises = db.execute("SELECT exercise_name, routine_id FROM exercises WHERE user_id=:user_id", user_id=session["user_id"])
        routines = db.execute("SELECT routine_name, routine_id FROM routines WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_exercises.html", username=username[0]["username"], routines=routines, exercises=exercises)

    return render_template("error.html", message="Internal Server Error")


# default route to manage exercises
@app.route("/manage_exercises", methods=["GET"])
@login_required
def manage_exercises():

    # get info for display purposes
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        exercises = db.execute("SELECT exercise_name, routine_id FROM exercises WHERE user_id=:user_id", user_id=session["user_id"])
        routines = db.execute("SELECT routine_name, routine_id FROM routines WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("manage_exercises.html", username=username[0]["username"], routines=routines, exercises=exercises)

    return render_template("error.html", message="Internal Server Error")


# log an exercise
@app.route("/log_exercise", methods=["GET", "POST"])
@login_required
def log_exercise():

    if request.method == "POST":

        # get info from form
        routine_id = request.form.get("routine_id")
        exercise_name = request.form.get("exercise_name")
        sets = request.form.get("sets")
        reps = request.form.get("reps")
        weight = request.form.get("weight")

        # make sure values were submitted
        if not routine_id and exercise_name and sets and reps and weight:
            return render_template("error.html", message="Error [Please fill form correctly]")

        # insert into sessions table
        try:
            db.execute("""INSERT INTO sessions (user_id, routine_id, exercise_name, sets, reps, weight)
                        VALUES (:user_id, :routine_id, :exercise_name, :sets, :reps, :weight)""",
                        user_id=session["user_id"], routine_id=routine_id, exercise_name=exercise_name, sets=sets, reps=reps, weight=weight)
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        return redirect("/")

    return render_template("error.html", message="Internal Server Error")


# progress graph route
@app.route("/progress_graph", methods=["GET", "POST"])
@login_required
def progress_graph():

    if request.method == "POST":

        # flag for whether or not to show the graph
        display_graph = False

        # get info from form
        exercise_name = request.form.get("exercise_name")
        if not exercise_name:
            return render_template("error.html", message="Please select an exercise")

        # get all logged sessions for given exercise
        try:
            session_logs = db.execute("""SELECT weight, session_date, session_time
                                        FROM sessions WHERE user_id=:user_id AND exercise_name=:exercise_name""",
                                        user_id=session["user_id"], exercise_name=exercise_name)
        except IOError:
            return render_template("error.html", message="Internal System Error")

        if len(session_logs) < 1:
            return render_template("error.html", message="No Sessions Returned")

        # create figure to plot graph on
        fig = plt.figure()
        ax1 = fig.add_subplot(1, 1, 1)

        # lists to parse data to
        weights = []
        dates = []

        # parse weight, session date, and time
        for session_log in session_logs:
            weights.append(session_log["weight"])

            # combine date and time
            full_time = ""
            full_time = session_log["session_date"] + "\n" + session_log["session_time"]
            dates.append(full_time)

        # plot data
        ax1.plot(dates, weights, marker='o')

        # tilt date/time label 45 degrees to allow for more space
        for label in ax1.xaxis.get_ticklabels():
                label.set_rotation(45)

        # display grid
        ax1.grid(True)

        # axis labels
        ax1.set_xlabel("\nDates")
        ax1.set_ylabel("Weights", labelpad=5)

        # graph title
        plt.title(exercise_name+"\n")

        # spacing
        plt.subplots_adjust(left=0.13, bottom=0.28, right=0.96, top=0.87, wspace=0.2, hspace=0.2)

        # save to file
        plt.savefig("./static/progress_graph.pdf")

        # flag
        display_graph = True

        # get info for display purses
        try:
            username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
            exercises = db.execute("SELECT DISTINCT exercise_name FROM sessions WHERE user_id=:user_id", user_id=session["user_id"])
        except IOError:
            return render_template("error.html", message="Internal Server Error")

        return render_template("progress_graph.html", username=username[0]["username"], exercises=exercises, display_graph=display_graph, progress_graph="progress_graph.pdf")

    # get info for display purses
    try:
        username = db.execute("SELECT username FROM users WHERE user_id=:user_id", user_id=session["user_id"])
        exercises = db.execute("SELECT DISTINCT exercise_name FROM sessions WHERE user_id=:user_id", user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    return render_template("progress_graph.html", username=username[0]["username"], exercises=exercises)

    return render_template("error.html", message="Internal Server Error")


# route to obtain previous values for given exercise
@app.route("/get_prev_values", methods=["GET"])
@login_required
def get_prev_values():

    # get info from form
    routine_id = request.args.get("routine_id")
    exercise_name = request.args.get("exercise_name")
    if not routine_id and exercise_name:
        return render_template("error.html", message="Internal Server Error")

    try:
        prev_vals = db.execute("""SELECT sets, reps, weight
                                FROM sessions
                                WHERE routine_id=:routine_id
                                AND exercise_name=:exercise_name
                                AND user_id=:user_id
                                ORDER BY session_date DESC, session_time DESC LIMIT 1""",
                                routine_id=routine_id, exercise_name=exercise_name, user_id=session["user_id"])
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    if len(prev_vals) < 1:
        # display zeroes if no previous values in database
        my_dict = {'prev_sets' : 0, "prev_reps" : 0, "prev_weight" : 0}
        return jsonify(my_dict)
    else:
        # display previous values from database
        my_dict = {'prev_sets' : prev_vals[0]["sets"], "prev_reps" : prev_vals[0]["reps"], "prev_weight" : prev_vals[0]["weight"]}
        return jsonify(my_dict)

    # Something broke
    return render_template("error.html", message="Internal System Error")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    try:
        session.clear()
    except IOError:
        return render_template("error.html", message="Internal Server Error")

    # Redirect user to login form
    return redirect("/")