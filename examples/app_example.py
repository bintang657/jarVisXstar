from flask import Flask, request, g
from jarVisXstar.middleware.flask_middleware import JarVisXstarFlask

app = Flask(__name__)
jarvis = JarVisXstarFlask(app)

@app.route("/api/secure", methods=["POST"])
def secure():
    return {
        "status": "ok",
        "clean_data": g.clean_json,
        "message": "Data sudah disanitasi otomatis oleh jarVisXstar"
    }

if __name__ == "__main__":
    app.run(debug=False, port=8080)