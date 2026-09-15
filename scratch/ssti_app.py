from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    template = f"Hello {name}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(port=5002)
