from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def dashboard():
    return render_template("index.html", title="Dashboard")

@app.route("/planner")
def planner():
    return render_template("index.html", title="Study Planner", message="Planner module coming soon.")

@app.route("/assignments")
def assignments():
    return render_template("index.html", title="Assignment Breakdown", message="Assignments module coming soon.")

@app.route("/labs")
def labs():
    return render_template("index.html", title="Cyber Lab Tracker", message="Labs module coming soon.")

if __name__ == "__main__":
    app.run(debug=True)
