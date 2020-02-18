# -*- coding: utf-8 -*-
import random
import re
import os
import sqlite3 
from flask import Flask, abort, jsonify, redirect, request, g
from base64 import b64encode
from hashlib import blake2b

app = Flask(__name__)


DATABASE = 'database.db'


def db_init():
    db = sqlite3.connect(DATABASE)
    c = db.cursor()
    c.execute('''CREATE TABLE shortened  (url text, alias texti, UNIQUE(url))''')
 

def db_connection():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


def db_fetch(query, args=(), one=False):
    cur = db_connection().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def db_execute(query, args=()):
    cur = db_connection().execute(query, args)
    cur.close()
    db_connection().commit()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def root_dir():  # pragma: no cover
    return os.path.abspath(os.path.dirname(__file__))


def get_file(filename):  # pragma: no cover
    try:
        src = os.path.join(root_dir(), filename)
        return open(src).read()
    except IOError as exc:
        return str(exc)

def url_valid(url):
    """Validates a url by parsing it with a regular expression.

    Parameters:
    url - string representing a url to be validated.

    Return values:
    Boolean, indicating the validity of the url.
    """
    return re.match(regex, url) is not None


def shorten(url):
    """Shortens a url by generating a 9 byte hash, and then
    converting it to a 12 character long base 64 url friendly string.

    Parameters:
    url - the url to be shortened.

    Return values:
    String, the unique shortened url, acting as a key for the entered long url.
    """
    url_hash = blake2b(str.encode(url), digest_size=DIGEST_SIZE)

    b64 = b64encode(url_hash.digest(), altchars=b'-_')
    return b64.decode('utf-8')


def bad_request(message):
    """Takes a supplied message and attaches it to a HttpResponse with code 400.

    Parameters:
    message - string containing the error message.

    Return values:
    An object with a message string and a status_code set to 400.
    """
    response = jsonify({'message': message})
    response.status_code = 400
    return response



@app.route('/index', methods=['GET'])
def index():
    return get_file("index.html")


@app.route('/shorten_url', methods=['POST'])
def shorten_url():
    if not request.json:
        return bad_request('Url must be provided in json format.')
    
    if 'url' not in request.json:
        return bad_request('Url parameter not found.')
    
    url = request.json['url']
    # For redirection purposes, we want to append http at some point.
    if url[:4] != 'http':
        url = 'http://' + url

    if not url_valid(url):
        return bad_request('Provided url is not valid.')

    alias = shorten(url)
    try:
        db_execute("INSERT INTO shortened (url, alias) VALUES ('%s', '%s')" % (url, alias))
    except sqlite3.IntegrityError:
        rs = db_fetch("SELECT alias FROM shortened WHERE url='%s'" % url, one=True)
        alias = rs[0]

    return jsonify({'alias': alias}), 201


@app.route('/shorten_url', methods=['GET'])
def shorten_url_get():
    return bad_request('Must use POST.')


@app.route('/<alias>', methods=['GET'])
def get_shortened(alias):
    rs = db_fetch("SELECT url FROM shortened WHERE alias='%s'" % alias, one=True)
    print(rs)
    if rs is None: 
        return bad_request('Unknown alias.')

    return redirect(rs[0], code=302)


regex = re.compile(
        r'^(?:http)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
DIGEST_SIZE = 9  # 72 bits of entropy.

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
