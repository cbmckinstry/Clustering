from flask import Flask, render_template,request
import calculations
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':

        # Get inputs from form
        int1 = int(request.form['int1'])
        int2 = int(request.form['int2'])
        int3 = int(request.form['int3'])
        int4 = int(request.form['int4'])
        int5 = int(request.form['int5'])
        int_list = [int(x) for x in request.form['int_list'].split(',')]

        # Perform calculations
        results = calculations.cluster(int1, int2, int3, int4, int5, int_list)

        return render_template('index.html', results=results)

    return render_template('index.html', results=None)


if __name__ == '__main__':
    app.run()
