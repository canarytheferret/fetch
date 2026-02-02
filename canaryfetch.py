import os
import hashlib
import urllib
import json
import time
import codecs

def load():
    signatures = {}
    try:
        with open('signatures', 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                parts = [part.strip() for part in line.split('|')]
                if len(parts) == 3:
                    signature, extension, description = parts
                    signbytes = codecs.decode(signature.encode('utf-8'), 'unicode_escape').encode('latin1')
                    signatures[signbytes] = extension, description
    except Exception as exception:
        print(f'Error loading signatures: {exception}')
    return signatures
SIGNATURES = load()

def expand(filepath):
    with open(filepath, 'rb') as file:
        header = file.read(32)

        if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
            return 'WEBP', 'WebP Image'
        if header[:4] == b'RIFF' and header[8:12] == b'AVI ':
            return 'AVI', 'AVI Video'
        if header[:4] == b'RIFF' and header[8:12] == b'WAVE':
            return 'WAV', 'WAV Audio'

        if header[:4] == b'PK\x03\x04':
            file.seek(0)
            content = file.read(512)
            if b'word/' in content:
                return 'DOCX', 'Microsoft Word Document'
            elif b'xl/' in content:
                return 'XLSX', 'Microsoft Excel Spreadsheet'
            elif b'ppt/' in content:
                return 'PPTX', 'Microsoft PowerPoint Presentation'
            else:
                return 'ZIP', 'ZIP Archive'
    return None, None

def signatures(filepath):
    try:
        with open(filepath, 'rb') as file:
            return file.read(32)
    except Exception:
        return None

def detect(filepath):
    signature = signatures(filepath)
    if not signature:
        return None, 'Unable to read file.'
    for magic, (filetype, description) in SIGNATURES.items():
        if signature.startswith(magic):
            if magic in [b'RIFF', b'PK\x03\x04']:
                extension, description = expand(filepath)
                if extension:
                    return extension, description
            return filetype, description
    try:
        with open(filetype, 'r', encoding='utf-8') as file:
            file.read(1024)
        return 'TXT', 'Text Document'
    except:
        pass
    return 'UNKNOWN', 'Unknown File'

def extensions(filename):
    _, extension = os.path.splitext(filename)
    return extension[1:].upper() if extension else 'NONE'

def fetch(filepath, filename):
    extension = extensions(filename)
    filetype, description = detect(filepath)
    mismatch = False
    message = 'File type could not be determined.'
    if filetype == 'UNKNOWN':
        message = 'This type of file is not in our database. You can help add to it by filling out [PLACEHOLDER].'
    elif extension == 'NONE':
        message = f'This file has no extension, but we detected: `{filetype}`.'
        mismatch = True
    elif extension == filetype:
        message = f'This file\'s extension matches what we detected: `{filetype}`.'
    else:
        VARIATIONS = {
            'JPG': 'JPEG', 'JPEG': 'JPG',
            'HTM': 'HTML', 'HTML': 'HTM',
        }
        if VARIATIONS.get(extension) == filetype:
            message = f'This file\'s extension is a variation of what we detected: `{filetype}`.'
        else:
            message = f'This file\'s extension claims `{extension}` but we detected: `{filetype}`.'
            mismatch = True
    return {
        'filename': filename,
        'extension': extension,
        'detected_type': filetype,
        'detected_description': description,
        'mismatch': mismatch,
        'message': message
    }

def virustotal(filepath, API_KEY=None):
    if not API_KEY:
        API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
        if not API_KEY:
            return {
                'error': 'VirusTotal API is not configured.',
                'message': 'Please set \'VIRUSTOTAL_API_KEY\' variable in the web server\'s environment.'
            }
    try:
        SHA256 = hashlib.sha256()
        with open(filepath, 'rb') as file:
            for block in iter(lambda: file.read(4096), b''):
                SHA256.update(block)
        filehash = SHA256.hexdigest()
        connection = f'https://www.virustotal.com/api/v3/files/{filehash}'
        headers = {'x-apikey': API_KEY}
        request = urllib.request.Request(connection, headers=headers)
        try:
            response = urllib.request.urlopen(request)
            data = json.loads(response.read().decode())
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                'filehash': filehash,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'date': data['data']['attributes'].get('last_analysis_date'),
                'permalink': f'https://www.virustotal.com/gui/file/{filehash}',
                'status': 'clean' if stats.get('malicious', 0) == 0 else 'dirty'
            }
        except urllib.error.HTTPError as exception:
            if exception.code == 404:
                return {
                    'filehash': filehash,
                    'message': 'The file is not found in VirusTotal\'s database.',
                    'link': 'https://www.virustotal.com/gui/home/upload'
                }
            else:
                raise
    except Exception as exception:
        return {
            'error': 'Check failed.',
            'details': str(exception)
        }
