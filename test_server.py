from urllib.parse import urljoin

from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from aiohttp.web_app import Application

from server import init_app


class TestServer(AioHTTPTestCase):
    login = 'testuser'
    password = 'password'
    name = 'user'
    age = 0
    # auth = None
    auth = None

    async def get_application(self) -> Application:
        app = await init_app('sqlite:///mem.db')
        self.ok_msg = app['ok_msg']
        return app

    async def register_ok(self):
        user_dict = {
            'login': self.login,
            'password': self.password,
            'name': self.name,
            'age': self.age
        }
        resp = await self.client.request("POST", "/user", json=user_dict)
        assert resp.status == 200
        msg = ((await resp.json())['msg'])
        assert msg == self.ok_msg

    async def login_ok(self):
        login_dict = {
            'login': self.login,
            'password': self.password
        }
        resp = await self.client.request("POST", '/login', json=login_dict)
        assert resp.status == 200
        msg = (await resp.json())['msg']
        assert msg == self.ok_msg
        self.auth = (await resp.json())['auth']

    async def get_ok(self):
        print(self.auth, 'get')
        resp = await self.client.request("GET", '/user', json={'auth': self.auth})
        assert resp.status == 200
        data = (await resp.json())
        msg = data['msg']
        assert msg == self.ok_msg
        assert data['age'] == self.age
        assert data['name'] == self.name


    async def delete_ok(self):
        print(self.auth, 'delete')
        resp = await self.client.request('DELETE', '/user', json={'auth': self.auth})
        assert resp.status == 200
        msg = (await resp.json())['msg']
        assert msg == self.ok_msg

    async def note_post_ok(self, text):
        resp = await self.client.request('POST', '/notes', json={'auth': self.auth, 'text': text})
        assert resp.status == 200
        msg = (await resp.json())['msg']
        assert msg == self.ok_msg

    async def note_get_ids_ok(self):
        resp = await self.client.request('GET', '/notes', json={'auth': self.auth})
        assert resp.status == 200
        data = await resp.json()
        msg = data['msg']
        assert msg == self.ok_msg
        return data['note_ids']

    async def note_get_ok(self, id):
        resp = await self.client.request('GET', f'/notes/{id}', json={'auth': self.auth})
        assert resp.status == 200
        data = await resp.json()
        msg = data['msg']
        assert msg == self.ok_msg
        return data['text']

    async def note_update_ok(self, id, text):
        resp = await self.client.request('POST', f'/notes/{id}', json={'auth': self.auth, 'text': text})
        assert resp.status == 200
        msg = (await resp.json())['msg']
        assert msg == self.ok_msg

    @unittest_run_loop
    async def test_process(self):
        await self.register_ok()
        await self.login_ok()
        await self.get_ok()
        text = "1234567"
        await self.note_post_ok(text)
        ids = await self.note_get_ids_ok()
        assert len(ids) == 1
        note = await self.note_get_ok(ids[0])
        assert note == text
        text = "qwertty"
        await self.note_update_ok(ids[0], text)
        note = await self.note_get_ok(ids[0])
        assert note == text
        await self.delete_ok()
