from flask import Flask, render_template

app = Flask(__name__)

def execute_python_file():
    # Code to execute your Python file
    # For example, if your Python file is named 'script.py', you would run:
    exec(open('create_stego_image.py').read())
    pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/run-python-file', methods=['POST'])
def run_python_file():
    execute_python_file()
    return 'Python file executed successfully'

if __name__ == '__main__':
    app.run(debug=True)
