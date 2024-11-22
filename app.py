from flask import Flask, jsonify, render_template
from Crypto.PublicKey import RSA
import string
import base64
import random
import sqlite3

app = Flask(__name__)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                    (id TEXT PRIMARY KEY, private_key TEXT)''')
    conn.commit()
    conn.close()

init_db()

def test(key):
    return key.publickey().export_key().decode()

def get_private_key(key):
    return key.export_key().decode()

def get_public_key_base64(key):
    public_key = key.publickey().export_key()
    return base64.b64encode(public_key).decode()

def decode_public_key_base64(encoded_key):
    decoded_key = base64.b64decode(encoded_key)
    return RSA.import_key(decoded_key)

def get_private_key_base64(key):
    private_key = key.export_key()
    return base64.b64encode(private_key).decode()

def save_key_to_db(id, private_key):
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()
    c.execute("INSERT INTO keys (id, private_key) VALUES (?, ?)", (id, private_key))
    conn.commit()
    conn.close()

def get_keys_from_db():
    conn = sqlite3.connect('keys.db')
    c = conn.cursor()
    c.execute("SELECT id, private_key FROM keys")
    keys = [{'id': row[0], 'private_key': row[1]} for row in c.fetchall()]
    conn.close()
    return keys

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    global rand_string, key
    rand_string = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
    key = RSA.generate(2048)
    encoded_key = get_public_key_base64(key)
    save_key_to_db(rand_string, get_private_key_base64(key))
    return jsonify({'id': rand_string, 'public_key': encoded_key})

@app.route('/', methods=['GET'])
def view_keys():
    keys = get_keys_from_db()
    return render_template('view_keys.html', keys=keys)

if __name__ == '__main__':
    app.run(debug=True)