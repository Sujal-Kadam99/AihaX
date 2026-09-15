from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    if url:
        try:
            resp = requests.get(url, timeout=2)
            return resp.text
        except:
            return "Error fetching URL"
    return "No URL provided"

if __name__ == '__main__':
    app.run(port=5004)
