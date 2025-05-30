from flask import Flask, render_template, request, jsonify
from scanner import scan_code  # Import scanner function

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    code = request.form.get('code', '')
    results = scan_code(code)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)