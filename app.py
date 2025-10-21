from flask import Flask, render_template, request, redirect, url_for
from scanner import crawl_and_scan

app = Flask(__name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form.get('target')
        if not target:
            return render_template('index.html', error='Enter a target URL')
        # run scan (synchronous - minimal)
        report = crawl_and_scan(target, max_pages=20)
        return render_template('results.html', report=report)
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
