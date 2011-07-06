import mimetypes
import os


def to_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8', 'strict')
    else:
        return str(s)


def encode_multipart(boundary, data):
    """Ripped from django."""
    lines = []
    is_file = lambda thing: hasattr(thing, "read") and callable(thing.read)
    for key, value in data.items():
        if is_file(value):
            content_type = mimetypes.guess_type(value.name)[0]
            if content_type is None:
                content_type = 'application/octet-stream'
            lines.extend([
                '--' + boundary,
                'Content-Disposition: form-data; name="%s"; filename="%s"' \
                 % (to_str(key), to_str(os.path.basename(file.name))),
                'Content-Type: %s' % content_type,
                '',
                file.read(),
            ])
        else:
            lines.extend([
                '--' + boundary,
                'Content-Disposition: form-data; name="%s"' % to_str(key),
                '',
                to_str(value),
            ])

    lines.extend([
        '--' + boundary + '--',
        '',
    ])
    return '\r\n'.join(lines)
