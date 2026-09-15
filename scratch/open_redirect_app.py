from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def redir():
    url = request.args.get('url', '/')
    return redirect(url)

if __name__ == '__main__':
    app.run(port=5001)
