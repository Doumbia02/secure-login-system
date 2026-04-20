from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import time

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Track failed login attempts
failed_attempts = {}

# Create database
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password BLOB
        )
    """)
    conn.commit()
    conn.close()

init_db()

# 📝 LOGGING FUNCTION
def log_attempt(username, success):
    with open("log.txt", "a") as f:
        status = "SUCCESS" if success else "FAILED"
        f.write(f"{time.ctime()} - {username} - {status}\n")


# 🏠 HOME
@app.route("/")
def home():
    return redirect("/login")


# 📝 REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# 🔐 LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # 🚫 Brute-force protection (max 3 attempts)
        if username in failed_attempts:
            if failed_attempts[username]["count"] >= 3:
                if time.time() - failed_attempts[username]["time"] < 60:
                    return "❌ Too many attempts. Try again in 60 seconds."
                else:
                    failed_attempts[username]["count"] = 0

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        result = cursor.fetchone()
        conn.close()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
            session["user"] = username
            log_attempt(username, True)
            return redirect("/dashboard")

        else:
            log_attempt(username, False)

            if username not in failed_attempts:
                failed_attempts[username] = {"count": 1, "time": time.time()}
            else:
                failed_attempts[username]["count"] += 1
                failed_attempts[username]["time"] = time.time()

            return "❌ Invalid credentials"

    return render_template("login.html")


# 📊 DASHBOARD (protected)
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return f"🔥 Welcome {session['user']}! You are logged in."
    return redirect("/login")


# 🚪 LOGOUT
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
