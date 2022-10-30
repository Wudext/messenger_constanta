from datetime import datetime
from flask import Flask, request, abort
import json
import time

# БД пользователя в json вместо csv
user = 'users.json'
msg = 'messages.json'
data = json.load(open(user))
messages = json.load(open(msg))
app = Flask(__name__)


@app.route("/")
def hello():
    return 'Hello, World <a href="/status">Status</a>'


@app.route("/status")
def status_view():
    return {
        'status': True,
        'name': 'server',
        'time': datetime.now().strftime('%Y.%m.%d - %H:%M'),
    }


# Отправка публичного ключа по запросу
@app.route("/send_key", methods=['GET'])
def send_key():
    login = request.args['receiver']
    for i in range(len(data)):
        if data[i]["login"] == login:
            return {'key': data[i]['key']}


@app.route("/login", methods=['POST'])
def login_check():
    login = str(request.json['login'])
    for i in range(len(data)):
        if data[i]["login"] == login:
            if request.json['password'] != data[i]["password"]:
                abort(401)
            else:
                return {'ok': True}

    abort(404)


# Регистрация (с ключом)
@app.route("/reg", methods=['POST'])
def registration():
    for u in data:
        if request.json['login'] == u["login"]:
            abort(401)

    reg_data = {'login': request.json['login'],
                'password': request.json['password'],
                'name': request.json['name'],
                'key': request.json['key']}
    data.append(reg_data)

    with open(user, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return {'ok': True}


# Улучшенная обработка сообщений
@app.route("/send", methods=['POST'])
def send():
    message = {'sender': str(request.json['sender']), 'receiver': request.json['receiver'], 'time': time.time(),
               'msg_sender': request.json['msg_sender'], 'msg_receiver': request.json['msg_receiver']}
    messages.append(message)

    with open(msg, "w") as f:
        json.dump(messages, f, indent=2, ensure_ascii=False)

    return {'ok': True}


@app.route("/users")
def users():
    users = []
    logins = []

    for i in range(len(data)):
        users.append(data[i]["name"])
        logins.append(data[i]["login"])

    return {'users': users, 'logins': logins}


def filter_dicts(elements, key, min_value):
    new_elements = []

    for element in elements:
        if element[key] > min_value:
            new_elements.append(element)

    return new_elements


@app.route("/messages")
def messages_view():
    after = float(request.args.get('after'))
    login = str(request.args.get('login', None))
    m = []

    for message in messages:
        if message["receiver"] == login or message["sender"] == login:
            m.append(message)
            del message

    filtered_messages = filter_dicts(m, key='time', min_value=after)

    return {'messages': filtered_messages}


app.run()
