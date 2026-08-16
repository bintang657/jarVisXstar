import requests
from flask import Flask, request, Response
from jarVisXstar.middleware.flask_middleware import JarVisXstarFlask

app = Flask(__name__)
JarVisXstarFlask(app)

TARGET_URL = "https://clideo.com/id/video-converter"

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def proxy(path):
    target_url = f"{TARGET_URL}/{path}"
    resp = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for key, value in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False,
        stream=True
    )
    return Response(
        resp.iter_content(chunk_size=1024),
        status=resp.status_code,
        headers=dict(resp.headers)
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)