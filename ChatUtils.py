from __future__ import annotations

from os import urandom
from typing import Dict, List
import logging
import hashlib


logger = logging.getLogger(__name__)


class RoomUser:
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip

    def get_name(self):
        return self.name

    def get_ip(self):
        return self.ip

    def __eq__(self, other: RoomUser or str) -> bool:
        if isinstance(other, RoomUser):
            return self.ip == other.ip
        if isinstance(other, str):
            return self.ip == other
        raise TypeError


class Singleton(type):
    _obj = {}

    def __call__(cls, *args, **kwargs):
        return cls._obj[cls] if cls in cls._obj else cls._obj.setdefault(cls, super().__call__(*args, **kwargs))


class ChatRooms(metaclass=Singleton):
    rooms = Dict[str, List[RoomUser]]

    def __init__(self):
        self.rooms: Dict[str: List[RoomUser]] = dict()
        self.access: Dict[str: str] = dict()

    def __len__(self):
        return len(self.rooms)

    def room_names(self):
        return list(self.rooms.keys())

    def room_exists(self, room_name: str) -> bool:
        return room_name in self.rooms

    def delete_empty_rooms(self):
        for room in [_ for _ in self.rooms if len(self.rooms[_]) == 0]:
            del self.rooms[room]
            del self.access[room]
            logging.info('>>> deleted empty room', room)
        return True

    def get_users_of_room(self, name) -> list or None:
        return self.rooms.get(name) or (self.delete_empty_rooms() or None)

    def get_usernames_of_room(self, room_name: str) -> list or None:
        return [
            _.get_name() for _ in self.rooms[room_name]
        ] or (
            self.delete_empty_rooms() or None
        ) if room_name in self.rooms else None

    def is_username_in_room(self, username: str or RoomUser, room_name: str) -> bool:
        name = username.get_name() if isinstance(username, RoomUser) else username
        return any(name == user.get_name() for user in self.rooms.get(room_name, []))

    def is_user_in_room(self, user: RoomUser, room_name: str) -> bool:
        return any(user == next_user for next_user in self.rooms.get(room_name, []))

    def is_ip_in_room(self, ip: str, room_name: str) -> bool:
        return any(user == ip for user in self.rooms.get(room_name, []))

    def list_rooms_where_ip(self, ip: RoomUser or str) -> List[str]:
        return sorted({room for room in self.rooms if any(ip == user for user in self.rooms[room])})

    def join_user_to_room(self, user: RoomUser, room_name: str, password: str) -> bool:
        if room_name not in self.rooms:
            self.rooms[room_name], self.access[room_name] = [user], password
            return True
        if self.access[room_name] == password and not self.is_user_in_room(user, room_name):
            return (self.rooms[room_name].append(user), True)[-1]
        return False

    def unjoin_user_from_room(self, user: RoomUser, room: str) -> bool:
        if self.is_user_in_room(user, room):
            self.rooms[room] = [u for u in self.rooms[room] if u != user]
            logger.info(f'deleted User object in room {room}, room len={len(self.rooms[room])}')
            return True
        return False

    def unjoin_ip_everywhere(self, ip: str) -> list:
        return [(room, RoomUser(self.name_by_ip_in_room(room, ip), ip).get_name())
                for room in self.rooms if self.is_ip_in_room(ip, room) and
                self.unjoin_user_from_room(RoomUser(self.name_by_ip_in_room(room, ip), ip), room)]

    def name_by_ip_in_room(self, room_name, ip) -> bool or str:
        return next((user.get_name() for user in self.rooms.get(room_name, []) if ip == user), False)


class Tokens:
    def __init__(self, temp_hash):
        self.temp_hash = temp_hash
        self.tokens = {}

    def set_token(self, **d):
        d['temp_hash'] = self.temp_hash
        key = hashlib.sha512(''.join(f'{k}: {d[k]}' for k in sorted(d.keys())).encode('utf-8')).hexdigest()
        self.tokens[key] = d
        return key

    def remove_token(self, token):
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False

    def is_valid(self, **d):
        d['temp_hash'] = self.temp_hash
        return hashlib.sha512(
            ''.join(f'{k}: {d[k]}' for k in sorted(d.keys())).encode('utf-8')
        ).hexdigest() in self.tokens

    def __str__(self):
        result = ''
        for k, v in self.tokens.items():
            result += f'{k}: {v}\n'
        return result


def test1():
    rooms = ChatRooms()
    print(rooms.join_user_to_room(RoomUser("alex", "192.168.1.1"), "room1", "passwd"))
    print(rooms.join_user_to_room(RoomUser("alexx", "192.168.1.3"), "room1", "passwdx"))
    print(rooms.is_ip_in_room("192.168.1.1", "room11"))
    print(rooms.list_rooms_where_ip("192.168.1.1"))
    print(rooms.name_by_ip_in_room("room1", "192.168.1.1"))

    t = Tokens(urandom(64).hex())
    t.set_token(roomname='roomname', user='user', password='password')
    t.set_token(roomname='roomname1', user='user1', password='password1')

    print(t.is_valid(roomname='roomname', password='password', user='user'))


if __name__ == "__main__":
    test1()
