"""Intentionally vulnerable LOCAL teaching application. Do not deploy publicly."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import json
import sqlite3

HOST = '127.0.0.1'
PORT = 8000


def create_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript('''
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, content TEXT);
        INSERT INTO users VALUES (1, 'alice', 'apple123'), (2, 'bob', 'banana456');
        INSERT INTO notes VALUES (1, 1, 'Alice private note'), (2, 2, 'Bob private note');
    ''')
    return conn


DB = create_db()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, obj):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        params = parse_qs(url.query)
        if url.path == '/login':
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            # VULNERABILITY 1: untrusted data interpolated into SQL string.
            query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
            try:
                row = DB.execute(query).fetchone()
            except sqlite3.Error:
                return self.reply(400, {'error': 'Invalid query'})
            return self.reply(200 if row else 401, {'user': dict(row)} if row else {'error': 'Invalid credentials'})
        if url.path == '/notes':
            try:
                note_id = int(params.get('id', [''])[0])
                user_id = int(params.get('user_id', [''])[0])
            except ValueError:
                return self.reply(400, {'error': 'id and user_id must be integers'})
            # VULNERABILITY 2: note ownership is not checked.
            row = DB.execute('SELECT id, owner_id, content FROM notes WHERE id = ?', (note_id,)).fetchone()
            return self.reply(200, {'note': dict(row), 'requester': user_id} if row else {'error': 'Note not found'})
        return self.reply(404, {'error': 'Unknown endpoint'})


if __name__ == '__main__':
    print(f'LOCAL TRAINING ONLY: http://{HOST}:{PORT}', flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
