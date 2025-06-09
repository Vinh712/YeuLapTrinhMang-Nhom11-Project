from flask import Flask, request, Response
import requests
from itertools import cycle

app = Flask(__name__)
BACKENDS = cycle([
    "http://127.0.0.1:5000",
    "http://127.0.0.1:5001",
    "http://127.0.0.1:5002",
])

@app.route('/', defaults={'path': ''}, methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
@app.route('/<path:path>', methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS'])
def proxy(path):
    backend = next(BACKENDS)
    url = f"{backend}/{path}"
    # CHỖ SỬA: dùng .items() và bỏ dấu phẩy
    headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}

    # Forward
    resp = requests.request(
        method         = request.method,
        url            = url,
        params         = request.args,
        headers        = headers,
        json           = request.get_json(silent=True),
        data           = request.get_data(),
        cookies        = request.cookies,
        allow_redirects= False,
    )

    # Trả về cho client
    excluded = {'content-encoding','content-length','transfer-encoding','connection'}
    out_headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
    return Response(resp.content, resp.status_code, out_headers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
