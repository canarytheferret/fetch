import os

import fetch_signatures

def get_header(filepath, size=32):
    try:
        with open(filepath, 'rb') as file:
            return file.read(size)
    except Exception:
        return None

def compound_file(filepath, header):
    if header[:4] == b'RIFF':
        if header[8:12] == b'WEBP':
            return 'WEBP', 'WebP Image'
        if header[8:12] == b'AVI ':
            return 'AVI', 'AVI Video'
        if header[8:12] == b'WAVE':
            return 'WAV', 'WAV Audio'

    if header[:4] == b'PK\x03\x04':
        try:
            with open(filepath, 'rb') as file:
                file.seek(0)
                # Read enough to find Office xml signatures
                content = file.read(2048)
                if b'word/' in content:
                    return 'DOCX', 'Microsoft Word Document'
                elif b'xl/' in content:
                    return 'XLSX', 'Microsoft Excel Spreadsheet'
                elif b'ppt/' in content:
                    return 'PPTX', 'Microsoft PowerPoint Presentation'
                else:
                    return 'ZIP', 'ZIP Archive'
        except Exception:
            return 'ZIP', 'ZIP Archive'
    return None, None

def find_filetype(filepath):
    header = get_header(filepath)
    if not header:
        return None, 'Sorry! Unable to read file.'

    for signature, (filetype, description) in fetch_signatures.SIGNATURES.items():
        if header.startswith(signature):
            if signature in [b'RIFF', b'PK\x03\x04']:
                filetype, description = compound_file(filepath, header)
                if filetype:
                    return filepath, description
            return filetype, description
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            file.read(1024)
        return 'TXT', 'Text Document'
    except Exception as exception:
        print(f'WARN: {exception}')
        pass
    return 'UNKNOWN', 'Unknown File'

def get_filetype(filename):
    _, ext = os.path.splitext(filename)
    return ext[1:].upper() if ext else 'NONE'

def scan(filepath, filename):
    original_filetype = get_filetype(filename)
    filetype, description = find_filetype(filepath)
    mismatch = False
    message = 'Sorry! File type could not be determined.'
    if filetype == 'UNKNOWN':
        message = 'Sorry! File type is not in our database.'
    elif original_filetype == 'NONE':
        message = f'File has no extension; we detected: "`{filetype}`."'
        mismatch = True
    elif original_filetype == filetype:
        message = f'File type is {original_filetype}; we detected: "`{filetype}`."'
    else:
        variations = {
            'JPG': 'JPEG', 'JPEG': 'JPG',
            'HTM': 'HTML', 'HTML': 'HTM',
            'TIF': 'TIFF', 'TIFF': 'TIF'
        }
        if variations.get(original_filetype) == filetype:
            message = f'File type is a valid variation of what we detected: "`{filetype}`."'
        else:
            message = f'File type is not "`{original_filetype}`"; we detected: "`{filetype}`."'
            mismatch = True
    return {
        'filename': filename,
        'original_filetype': original_filetype,
        'filetype': filetype,
        'description': description,
        'mismatch': mismatch,
        'message': message
    }