from flask import Flask, render_template, request, session
import calculations
import os
app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey")

@app.route('/', methods=['GET', 'POST'])
def index():
    user_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    user_agent = request.headers.get("User-Agent", "").lower()
    is_bot = (
            "go-http-client/" in user_agent
            or "cron-job.org" in user_agent
            or user_agent.strip() == ""
    )
    if str(user_ip) != '127.0.0.1' and not is_bot:
        print("Viewer IP: "+str(user_ip))
    if request.method == 'POST':
        try:
        # Get inputs from form
            int1 = int(request.form['int1'])
            int2 = int(request.form['int2'])
            int3 = int(request.form['int3'])
            int4 = int(request.form['int4'])
            int5 = int(request.form['int5'])
            int_list = [int(x) for x in request.form['int_list'].split(',')]

            print("User IP: " +str(user_ip)+", Single Sites: "+ str(int1) + ", Double Sites: " + str(int2) + ", Triple Sites: " + str(int3) + ", Cars: " +str(int4) + ", Vans: " +str(int5) + ", Bus Caps: "+str(int_list))


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