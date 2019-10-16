from _hashlib import openssl_md5
from random import random, randint

from aiohttp import web
from aiohttp.web_app import Application
from logzero import logger
from sqlalchemy import create_engine


def auth(data, db):
    # check if request is authorized in db
    if not validate(data):
        return False, web.json_response(data={'msg': 'invalid_data'})
    token = data['auth']
    command = f'select uname, token from sessions where token = "{token}"'
    ok, r = db_request(command, db, 'Authentication error')
    if not ok:
        return r

    if not r:
        return False, web.json_response({'msg': 'Authentication error'})
    meta = {'uname': r[0][0]}
    return True, meta


def db_request(command, db, emsg='Error'):
    try:
        r = db.execute(command)
        return r.fetchall()
    except Exception as e:
        logger.error(e)
        return False, web.json_response({'msg': emsg})


def hash(s):
    return openssl_md5(s.encode('utf-8')).hexdigest()


def validate(data, template=None):
    return True


async def register(request):
    db = request.app['con']
    data = await request.json()
    if not validate(data):
        return web.json_response(data={'msg': 'Invalid data'})

    uname = data['login']
    password = data['password']
    phash = hash(password)
    name = data['name']
    age = data['age']
    command = f'insert into users (uname, phash, name, age) values ' \
              f'("{uname}", "{phash}", "{name}", {age})'
    ok, r = db_request(command, db, 'Login exists')
    if not ok:
        return r
    return web.json_response(data={'msg': request.app['ok_msg']})


async def login(request):
    db = request.app['con']
    data = await request.json()
    if not validate(data):
        return web.json_response(data={'msg': 'Invalid data'})
    uname = data['login']
    password = data['password']
    phash = hash(password)
    command = f'select phash from users where uname = "{uname}"'
    ok, r = db_request(command, db)
    if not ok:
        return r

    if not r or phash != r[0][0]:
        return web.json_response(data={'msg': 'Invalid login or password'})

    token = hash(f'{random()}{random()}{random()}')
    command = f'insert into sessions (uname, token) values ("{uname}", "{token}")'
    try:
        db.execute(command)
    except Exception as e:
        logger.error(e)
        return web.json_response(data={'msg': "Error"})
    return web.json_response(data={'auth': token, 'msg': request.app['ok_msg']})


async def info(request):
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    if not ok:
        return meta
    command = f'select name, age from users where uname = "{meta["uname"]}"'
    ok, r = db_request(command, db)
    if not ok:
        return r
    if not r or len(r[0]) != 2:
        return web.json_response(data={'msg': 'Error'})
    return web.json_response(data={'msg': request.app['ok_msg'], 'age': r[0][1], 'name': r[0][0]})


async def delete(request):
    """
    Delete user session
    Delete user
    Delete user notes
    :param request:
    :return:
    """
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    if not ok:
        return meta
    if not validate(meta):
        return web.json_response(data={'msg': 'invalid data'})
    logger.info(meta)
    command = f'delete from sessions where uname = "{meta.get("uname")}"'
    ok, r = db_request(command, db)
    if not ok:
        return r
    command = f'delete from users where uname = "{meta.get("uname")}"'
    ok, r = db_request(command, db)
    if not ok:
        return r

    return web.json_response(data={'msg': request.app['ok_msg']})


async def note_create(request):
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    if not ok:
        return meta
    if not validate(data) or not validate(meta):
        return web.json_response(data={'msg': 'invalid input'})
    command = f'insert into notes (text, note_id, uname) values ' \
              f'("{data["text"]}", "{meta["uname"]}", "{randint(1, 10 ** 9)}")'
    ok, r = db_request(command, db)
    if not ok:
        return r
    return web.json_response(data={"msg": request.app['ok_msg']})


async def notes_get(request):
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    if not ok:
        return meta
    if not validate(data) or not validate(meta):
        return web.json_response(data={'msg': 'invalid input'})
    command = f'select note_id from notes where uname = "{meta["uname"]}"'
    ok, r = db_request(command, db)
    if not ok:
        return r
    ids = [x[0] for x in r]
    return web.json_response(data={'msg': request.app['ok_msg'], 'note_ids': ids})


async def note_get(request):
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    note_id = request.match_info.get('note_id')
    if not ok:
        return meta
    if not validate(data) or not validate(meta) or note_id is None:
        return web.json_response(data={'msg': 'invalid input'})

    command = f'select text from notes where note_id = "{note_id}" and uname = "{meta["uname"]}"'
    ok, r = db_request(command, db)
    if not ok:
        return r
    return web.json_response(data={'msg': request.app['ok_msg'], 'text': r[0][0]})


async def note_update(request):
    db = request.app['con']
    data = await request.json()
    ok, meta = auth(data, db)
    note_id = request.match_info.get('note_id')
    if not ok:
        return meta
    if not validate(data) or not validate(meta) or note_id is None:
        return web.json_response(data={'msg': 'invalid input'})

    command = f'update notes set text = "{data["text"]}" where note_id = "{note_id}" and uname = "{meta["uname"]}"'
    ok, r = db_request(command, db)
    if not ok:
        return r
    return web.json_response(data={'msg': request.app['ok_msg']})


async def init_app(connection_string) -> Application:
    app = web.Application()
    engine = create_engine(connection_string)
    con = engine.connect()

    app['engine'] = engine
    app['con'] = con
    app['ok_msg'] = 'SUCCESS'
    app.add_routes([
        web.post('/user', register),
        web.get('/user', info),
        web.delete('/user', delete),
        web.post('/login', login),
        web.post('/notes', note_create),
        web.get('/notes', notes_get),
        web.get('/notes/{note_id}', note_get),
        web.post('/notes/{note_id}', note_update)
    ])
    return app


if __name__ == '__main__':
    app = init_app('sqlite:///mem.db')
    web.run_app(app, host='localhost', port=5000)
