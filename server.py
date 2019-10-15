from functools import wraps

from aiohttp import web


def auth(f):
    @wraps(f)
    def auth_wrapper(*args, **kwargs):
        # check if request is authorized in db
        return f(*args, **kwargs)
    return auth_wrapper


async def register(request):
    return


async def login(request):
    return


@auth
async def info(request):
    return


@auth
async def delete(request):
    return


app = web.Application()
app.add_routes([
    web.post('/user', register),
    web.get('/user', info),
    web.delete('/user', delete),
    web.post('/login', login)
])
if __name__ == '__main__':
    web.run_app(app, host='localhost', port=5000)
