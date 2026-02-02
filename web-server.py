import flask
import os
import werkzeug.utils
import canaryfetch

UPLOAD_FOLDER = 'uploads'

server = flask.Flask(__name__)
server.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
server.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@server.route('/')
def index():
    return flask.send_file('static/index.html')

@server.route('/check', methods=['POST'])
def check():
    if 'file' not in flask.request.files:
        return flask.jsonify({'error': 'No file was uploaded.'}), 400
    file = flask.request.files['file']
    if file.filename == '':
        return flask.jsonify({'error': 'No file selected.'}), 400
    if file:
        filename = werkzeug.utils.secure_filename(file.filename)
        filepath = os.path.join(server.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        result = canaryfetch.fetch(filepath, filename)
        if result['mismatch'] and flask.request.form.get('virustotal') == 'true':
            virustotal = canaryfetch.virustotal(filepath)
            result['virustotal'] = virustotal
        return flask.jsonify(result)
    return flask.jsonify({'error': 'File processing failed.'}), 500

if __name__ == '__main__':
    server.run(debug=True, host='0.0.0.0', port=5000)