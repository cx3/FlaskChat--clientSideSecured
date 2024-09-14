import socket
import logging
from os import urandom
from json import dumps
from datetime import timedelta, datetime

import pytz
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_socketio import SocketIO, send, join_room, emit

from ChatUtils import RoomUser, ChatRooms, Tokens


app = Flask(__name__)
app.config['SECRET_KEY'] = urandom(64).hex()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
socketio = SocketIO(app)
rooms = ChatRooms()
tokens = Tokens(app.config['SECRET_KEY'])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/', methods=['GET'])
def index_route():
    return redirect('/rooms')


@app.route('/rooms', methods=['GET'])
def rooms_route():
    if len(rooms):
        return ''.join(f'<a href="/chat/{name}">{name} {len(rooms.get_usernames_of_room(name))}</a><br>'
                       for name in rooms.room_names())
    return redirect('/create')


@app.route('/ip')
def get_ip_route():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


@app.route('/ask', methods=['POST', 'GET'])
def ask_route():
    args, keys = request.args, list(request.args.keys())

    if len(args) == 0:
        if request.is_json:
            args = request.get_json()
            keys = list(args.keys())

    logger.info(f'/ask   client requested: {args}')
    mode = args.get('mode', False)

    if mode == 'create':
        logger.info('/ask mode: create')
        if 'room_name_free' in keys:
            logger.info('/ask - is room name free...')
            return jsonify({"room_name_free": not rooms.room_exists(args['room_name_free'])})

    if mode == 'login':
        if 'room_name_free' in keys and 'user_name_free' not in keys:
            logger.info('/ask - room name free?')
            return jsonify({"room_name_free": not rooms.room_exists(args['room_name_free'])})

        if 'room_name_free' in keys and 'user_name_free' in keys:
            logger.info('/ask - room already created, is username free?')
            return jsonify({
                "room_name_free": not rooms.room_exists(args['room_name_free']),
                "user_name_free": not rooms.is_username_in_room(args["user_name_free"], args["room_name_free"])
            })
    return jsonify({"msg": "incorrect query error"})


def sanitize(s):
    return s.replace('<', '').replace('>', '').replace('$', '').replace('{', '').replace('}', '').strip(' ')


@app.route('/create', methods=['POST', 'GET'])
def create_new_room_route():

    if request.method == 'GET':
        return render_template('create.html', roomname=request.args.get('next', False))

    if request.method == 'POST':
        room_name = request.form.get('roomname', False)
        user_name = request.form.get('username', False)
        passwd = request.form.get('password', False)

        if room_name and user_name and passwd:
            room_name, user_name = sanitize(room_name), sanitize(user_name)
            user = RoomUser(user_name, get_ip_route())

            if rooms.join_user_to_room(user, room_name, passwd):
                return redirect(url_for('chat_room_route', user_name=user_name, room_name=room_name))
            else:
                session['login_attempts'] += 1
                return render_template('create.html', error="Username busy or incorrect password")
        else:
            return render_template('create.html', error="Fill all fields")


def check_login_attempts():
    if 'login_attempts' not in session:
        session['login_attempts'] = 0
        session['last_attempt_time'] = datetime.now(pytz.UTC)

    if datetime.now(pytz.UTC) - session['last_attempt_time'] > timedelta(minutes=11):
        session['login_attempts'] = 0

    if session['login_attempts'] >= 5:
        future_time = datetime.now(pytz.UTC) + timedelta(minutes=11)
        formatted_time = future_time.strftime('%H:%M:%S')
        return render_template(
            'login.html',
            error=f"Too many failed login attempts. Please try again later at {formatted_time}.",
            roomname=request.args.get('next', False),
            attempts=session['login_attempts']
        )
    return None


@app.route('/login', methods=['POST', 'GET'])
def login_route():
    error_response = check_login_attempts()
    if error_response:
        return error_response

    if request.method == 'GET':
        return render_template('login.html', roomname=request.args.get('next', False))

    if request.method == 'POST':
        room_name = request.form.get('roomname', False)
        user_name = request.form.get('username', False)
        passwd = request.form.get('password', False)

        if room_name and user_name and passwd:
            room_name, user_name = sanitize(room_name), sanitize(user_name)
            user = RoomUser(user_name, get_ip_route())

            if rooms.join_user_to_room(user, room_name, passwd):
                session['login_attempts'] = 0
                return f"""
                <script>
                   window.location.href="/chat/{room_name}";
                </script>
                """
            else:
                session['login_attempts'] += 1
                session['last_attempt_time'] = datetime.now()
                return render_template(
                    'login.html',
                    username=user_name,
                    roomname=room_name,
                    attempts=session['login_attempts'],
                    error="Username busy or incorrect password"
                )
        else:
            return render_template('login.html', error="Fill all fields")


@app.route('/chat/<room_name>', methods=['POST', 'GET'])
def chat_room_route(room_name: str):
    if rooms.is_ip_in_room(request.remote_addr, room_name):
        addr = get_ip_route()
        user_name = rooms.name_by_ip_in_room(room_name, addr)
        token = tokens.set_token(ip=addr, user_name=user_name, room_name=room_name)

        return render_template(
            'chat-dark3.html',
            room_name=room_name,
            user_name=user_name,
            token=token
        )
    if rooms.room_exists(room_name):
        return redirect(url_for('login_route', roomname=room_name))
    return redirect(url_for("create_new_room_route", roomname=room_name))


@socketio.on('join')
def handle_join(data: dict):
    addr = get_ip_route()
    logger.info(f'socketio join route. data={data}')
    logger.info(f'request addr: {addr}')

    room: bool = data.get('room', False)
    username = data.get('username', False)
    token = data.get('token', False)
    
    if room and username and token:
        if tokens.is_valid(ip=addr, user_name=username, room_name=room):
            room: str
            join_room(room)

            names = rooms.get_usernames_of_room(room)
            emit('update_user_list', names, to=room)
            send(f'{data["username"]} has joined the room {room}.', room=room)


@socketio.on('unjoin')
def handle_unjoin(data: dict):
    logger.info('socketio unjoin data=', data)

    addr = get_ip_route()

    room = data.get('roomname', False)
    user = data.get('username', False)
    token = data.get('token', False)

    if room and user and token:
        room: str or bool
        logger.info('attempt to unjoin user from room...')
        if rooms.unjoin_user_from_room(RoomUser(user, addr), room):
            # update_user_list
            emit('update_user_list', rooms.get_usernames_of_room(room), to=room)
            send(f'{data["username"]} has left the room {room}.', room=room)


@socketio.on('connect')
def handle_connect():
    logger.info(f'Client connected {request.remote_addr}')


@socketio.on('disconnect')
def handle_disconnect(data=None):
    logger.info(f'Client disconnected  ip: {request.remote_addr}   data={data}')
    for room, user in rooms.unjoin_ip_everywhere(request.remote_addr):
        logger.info(f'> unjoined by ip in room {room}')
        users = rooms.get_users_of_room(room)
        if users:
            emit('update_user_list', rooms.get_usernames_of_room(room), to=room)


@socketio.on('logout')
def handle_logout(data):
    logger.info(f'handle logout, {data}')
    logger.info('addr: ', request.remote_addr)
    # print('User logged out:', request.sid)
    emit('message', f"{data['userName']} left from room", to=data["roomName"])
    emit('update_user_list', rooms.get_usernames_of_room(data['roomName']), to=data["roomName"])


@socketio.on('message')
def handle_message(data: dict):

    logger.info('recv message from client')
    if isinstance(data, dict):
        user = data.get('user_name', False)
        room = data.get('room_name', '')
        token = data.get('token', False)
        msg = data.get('message', False)

        if user and msg and room != '' and token:
            addr = get_ip_route()
            if tokens.is_valid(ip=addr, user_name=user, room_name=room):
                names = [_.get_name() for _ in rooms.get_users_of_room(room)]
                emit('update_user_list', names, to=room)
                send(f'{user}: {msg}', room=room)
            else:
                open('ALERTS.txt', 'a+').write(dumps({
                    'addr': addr,
                    user: user,
                    room: room,
                    'msg': msg,
                })+'\n')


@socketio.on('image')
def handle_image(data):
    room = data['room_name']
    emit('image', {
        'user_name': data['user_name'],
        'image': data['image'],
        'file_name': data['file_name']
    }, to=room)



def local_ip():
    # https://www.w3resource.com/python-exercises/python-basic-exercise-55.php    
    # The following code retrieves the local IP address of the current machine:
    # 1. Use 'socket.gethostname()' to get the local hostname.
    # 2. Use 'socket.gethostbyname_ex()' to get a list of IP addresses associated with the hostname.
    # 3. Filter the list to exclude any IP addresses starting with "127." (loopback addresses).
    # 4. Extract the first IP address (if available) from the filtered list.
    # 5. Print the obtained IP address to the console.

    # Step 1: Get the local hostname.
    local_hostname = socket.gethostname()

    # Step 2: Get a list of IP addresses associated with the hostname.
    ip_addresses = socket.gethostbyname_ex(local_hostname)[2]
    print(f'ip adressess: {ip_addresses}')
    # Step 3: Filter out loopback addresses (IPs starting with "127.").
    filtered_ips = [ip for ip in ip_addresses if not ip.startswith("127.")]

    # Step 4: Extract the first IP address (if available) from the filtered list.
    first_ip = filtered_ips[:1]

    # Step 5: Print the obtained IP address to the console.
    print('local ip:', first_ip[0])
    return first_ip[0]


if __name__ == '__main__':
    socketio.run(
        app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True, use_reloader=True, log_output=True
    )  # ssl_context='adhoc'
