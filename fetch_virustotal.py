import os
import hashlib
import urllib.request
import json
import urllib.error

def scan(filepath, api_key=None):
    if not api_key:
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if not api_key:
            return {
                'error': 'Sorry! Configuration error.',
                'message': 'VIRUSTOTAL_API_KEY (environment variable) is missing.'
            }
    try:
        filehash = hashlib.sha256()
        with open(filepath, 'rb') as file:
            for block in iter(lambda: file.read(4096), b''):
                filehash.update(block)
        filehash = filehash.hexdigest()
        connection = f'https://www.virustotal.com/api/v3/files/{filehash}'
        headers = {'x-apikey': api_key}
        request = urllib.request.Request(connection, headers=headers)
        try:
            with urllib.request.urlopen(request) as response:
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
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return {
                    'filehash': filehash,
                    'message': 'Sorry! File was not found in VirusTotal\'s database. You can upload it manually.',
                    'link': 'https://www.virustotal.com/gui/home/upload'
                }
            raise

    except Exception as exception:
        return {
            'error': 'Sorry! Scan failed.',
            'details': str(exception)
        }