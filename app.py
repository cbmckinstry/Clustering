from flask import Flask, render_template, request, session
import calculations
from flask_session import Session
import os
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_KEY_PREFIX"] = "session:"

Session(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
        # Get inputs from form
            int1 = int(request.form['int1'])
            int2 = int(request.form['int2'])
            int3 = int(request.form['int3'])
            int4 = int(request.form['int4'])
            int5 = int(request.form['int5'])
            int_list = [int(x) for x in request.form['int_list'].split(',')]

        # Perform calculations
            results = calculations.cluster(int1, int2, int3, int4, int5, int_list)
            session['int1']=int1
            session['int2']=int2
            session['int3']=int3
            session['int4']=int4
            session['int5']=int5
            session['int_list']=int_list

            return render_template('index.html', results=results, error_message=None)
        except Exception as e:
            return render_template('index.html',error_message=f"An error occurred: {str(e)}", results=None)
    return render_template('index.html', results=None, error_message=None)


if __name__ == '__main__':
    app.run()
