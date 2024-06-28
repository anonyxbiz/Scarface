# Scarface/Scarface.py
"""
Scarface - Asynchronous framework built on top of Quart to implement custom security, perfomance and efficiency in deploying python apps.
"""
from quart import Quart, request, jsonify, send_file, make_response, Response
from asyncio import run as asyncrun
from secrets import token_urlsafe
from ijson import items
from json import dump
from os.path import exists
from os import mkdir
from datetime import datetime as dt
from cryptography.fernet import Fernet
from os import environ
from sys import exit
from hmac import new as new_hmac
from hashlib import sha256
from base64 import urlsafe_b64encode

p = print

class Safe:
    def __init__(self) -> None:
        self.safe_key = environ.get("safe_key", False)
        if not self.safe_key:
            exit("Safe key not found in the environment!")

    async def tool(self, og: str, action: str):
        try:
            if action == "encrypt":
                data = Fernet(self.safe_key.encode()).encrypt(og.encode("utf-8")).decode('utf-8')
            elif action == "decrypt":
                data = Fernet(self.safe_key.encode()).decrypt(og.encode("utf-8")).decode('utf-8')
            
            return data
        except Exception as e:
            p(e)
            return False
        
safe = Safe()

class Logging:
    def __init__(self) -> None:
        pass
    async def log_data(self, data):
        data = str(data)
        p(data)
        return data
    
logger = Logging()

class User_db():
    def __init__(self, db_dir = "Database") -> None:
        self.safe_key = environ.get("safe_key", False)
        if not self.safe_key:
            exit("Safe key not found in the environment!")
        self.key = self.safe_key.encode()
        self.users = f"{db_dir}/users"
        self.user_identifier = None
        self.do = None
        self.user_data = None
        self.og_user_identifier = None
        self.user_file_name = None

    async def hashing_tool(self, og: str):
        try:
            h = new_hmac(self.key, og.encode('utf-8'), sha256)
            data = urlsafe_b64encode(h.digest()).decode('utf-8')
            return str(data).split('=')[0]
        except Exception as e:
            p(e)
            return False

    async def dir_name(self, user_identifier=None):
        if user_identifier:
            self.user_identifier = user_identifier
        self.user_identity = await self.hashing_tool(self.user_identifier)
        if self.user_identity:
            user_file_name = f"{self.users}/{str(self.user_identity)}.json"
        return user_file_name

    async def identities(self, user_file_name=None):
        if not self.user_file_name:
            if user_file_name:
                self.user_file_name = user_file_name
            else:
                self.user_file_name = await self.dir_name()
        if self.user_file_name:
            if self.do == "get_user":
                if exists(self.user_file_name):
                    database = []
                    with open(self.user_file_name, 'rb') as f:
                        db = items(f, 'item')
                        for item in db:
                            database.append(item)

                    return ("user_found", database[0])
                else:
                    return (None, None)
                
            elif self.do == "create_user":
                if exists(self.user_file_name):
                    return (None, self.user_file_name)
                else:
                    with open(self.user_file_name, "w") as f:
                        dump([self.user_data], f, indent=4)
                        return ("user_created", self.user_file_name)
            
            elif self.do == "update_user":
                if exists(self.user_file_name) and self.user_data:
                    with open(self.user_file_name, "w") as f:
                        dump([self.user_data], f, indent=4)
                        return ("user_updated", self.user_file_name)
                else:
                    return (None, "user_not_found")
            else:
                return (None, self.user_file_name)

    async def user_management(self, user_identifier=None, do=None, data=None, user_file_name=None):
        if user_file_name:
            self.user_file_name = user_file_name
        self.og_user_identifier, self.user_identifier, self.do, self.user_data = user_identifier, str(user_identifier), do, data

        job = await self.identities()
        return job
            
user_db = User_db()

class Protect:
    def __init__(self, parent_instance, db_dir = "Database") -> None:
        self.parent_instance = parent_instance
        self.db_dir = db_dir
        self.db = f"{db_dir}/db.json"
        self.users = f"{db_dir}/users"
        self.allowed_hosts = ["127.0.0.1:8001"]
        self.max_seconds = 3600
        self.static_dir = "static/"
        self.protect_data = False

    async def how_old_is_the(self, token):
        data = []
        rounds = 1
        subject = token

        while rounds <= 2:
            hours, minutes, seconds = subject.split(":")
            seconds = int(int(hours) * 60 + int(minutes)) * 60 + float(seconds)
            data.append(seconds)
            subject = str(dt.now().time())
            rounds += 1

        data = data[1] - data[0]
        return (data, "Seconds")

    async def is_the_token_expired(self, user):
        return user
        data = await self.how_old_is_the(user["token_gen_at"])
        token_age = data[0]

        if token_age > self.max_seconds:
            return False
        else:
            return token_age

    async def rate_limit(self):
        try:
            identities = await self.update_db('read', None, 'rate_limits.json')           
            if identities != []:
                for x, y in enumerate(identities):
                    if self.parent_instance.ip == y["ip"]:
                        data = await self.how_old_is_the(y["last_set"])

                        token_age = data[0]
                        if token_age <= 60:
                            if y["hits"] >= 10:
                                return False
                            else:
                                identities[x]["hits"] += 1
                                identities[x]["total_hits"] += 1
                        else:
                            identities[x] = {"ip": self.parent_instance.ip, "total_hits": 1, "hits": 1, "last_set": str(dt.now().time()), "user_added_on": str(dt.now().time())}
                            
            else:
                user = {"ip": self.parent_instance.ip, "total_hits": 1, "hits": 1, "last_set": str(dt.now().time()), "user_added_on": str(dt.now().time())}
                identities.append(user)

            await self.update_db('update', identities, 'rate_limits.json')
            return True

        except Exception as e:
            p(e)
            return False

    async def jwt_token_gen(self, auth_key, index):
        try:
            jwt_token = await safe.tool(str(f"csrf_middleware>{str(auth_key)}|generated_at>{str(dt.now().time())}|identity_index>{str(index)}"), "encrypt")
            return jwt_token
        except Exception as e:
            p(e)
            return False

    async def get_jwt_data(self, jwt_token):
        try:
            jwt_data = await safe.tool(jwt_token, "decrypt")
            return jwt_data
        except Exception as e:
            p(e)
            return False

    async def session_manager(self, auth_key=None, do=None, jwt_token=None, index=None):
        if do == "gen" and auth_key:
            jwt_token = await self.jwt_token_gen(str(auth_key), str(index))
            if jwt_token:
                return jwt_token

        elif do == "index" and jwt_token:
            jwt_data = await self.get_jwt_data(jwt_token)
            if not jwt_data:
                return False
            
            try:
                data = (jwt_data.split("|"))
                identity_index = data[2].split(">")[1]
                return identity_index
            except:
                return None

    async def csrf_verification(self, data, headers):
        self.indentity_data, self.identity_headers = data, headers

        self.csrf_data = None
        self.parent_instance.jwt_token = None
        self.parent_instance.jwt_token = headers.get("x-jwt_token", False)

        host_app = headers.get("Host", False)
        if not host_app:
            host_app = headers.get("authority", False)
        if not host_app:
            host_app = headers.get("Origin", False).replace("https://", "").replace("http://", "")

        for domain in self.allowed_hosts:
            if domain not in str(host_app):
                return False, "Understandable but i'm not gonna work with that kind of request"

        if not self.parent_instance.jwt_token:
            self.parent_instance.jwt_token = data.get("jwt_token", False)

        if not self.parent_instance.jwt_token:
            self.parent_instance.jwt_token = None
            return False, "jwt_token is missing on your request"
        
        try:
            user_data_file = await self.session_manager(None, "index", self.parent_instance.jwt_token)
            if not user_data_file:
                return False, "Invalid or expired jwt_token"
            else:
                user_data = await user_db.user_management(user_data_file, "get_user")
                if not user_data:
                    return False, "Invalid or expired jwt_token"
                else:
                    self.parent_instance.user_file_name = user_data_file
                    self.csrf_data = self.parent_instance.jwt_token
                    return True, self.csrf_data
                
        except Exception as e:
            await logger.log_data(e)
        return False, self.csrf_data

class Middleware:
    def __init__(self, app, comps) -> None:
        self.app = app
        self.comps = comps
        self.db = "db.json"
        self.protected_routes = ["/api/"]
        self.allowed_methods = 'GET, POST'
        self.jwt_token = None
        self.ip = None
        self.request_url = None
        self.protect = Protect(self)
        self.user_file_name = None
        self.return_exception = None

    async def endpoint_validation(self):
        try:
            if not self.csrf_middleware:
                self.return_exception = jsonify({'error': "csrf_middleware is missing from your request."}), 406
            else:
                user_file_name = await self.protect.get_jwt_data(self.csrf_middleware)
                if user_file_name:
                    try:
                        self.user_file_name = str(user_file_name).split('csrf_middleware>')[1].split("|")[0]
                        get_user = await user_db.user_management(user_file_name=self.user_file_name, do="get_user")
                        if get_user[0]:
                            pass
                        else:
                            self.return_exception = jsonify({'error': "We did not find an identity connected to this csrf_middleware"}), 403
                    except:
                        self.return_exception = jsonify({'error': "Unable to validate your csrf_middleware, please try again later"}), 409
                else:
                    self.return_exception = jsonify({'error': "Invalid or expired csrf_middleware"}), 406
        except Exception as e:
            await logger.log_data(e)
            self.return_exception = jsonify({'error': "Something went wrong"}), 403
        
    async def before_request(self):
        self.csrf_middleware, self.ip, self.user_file_name, self.return_exception, self.req_type, self.take_it_easy = None, None, None, None, request.method, True

        self.ip = request.headers.get("X-Forwarded-For", None)
        if not self.ip:
            self.ip = request.headers.get("X-Forwarded-For", "None")

        self.request_url = str(request.url)
        await logger.log_data(f"Processing request from {self.ip}:>> {self.req_type}@ {self.request_url}")

        for x in self.protected_routes:
            if x in self.request_url:
                self.take_it_easy = False
                break

        if self.req_type not in self.allowed_methods:
            return jsonify({'error': "We understand what you're asking for, but we currently do not support this method"}), 407

        if not self.take_it_easy:
            if self.req_type == "GET":
                headers = request.headers
                data = request.args
            elif self.req_type == "POST":
                headers = request.headers

                if 'multipart' in str(headers.get("Content-Type", "Content-Type")):
                    data = headers
                else:
                    data = await request.get_json()
            else:
                return jsonify({'error': "Unexpected server error"}), 500

            self.headers, self.data = headers, data
            if not self.headers or not self.data:
                return jsonify({'error': "Some required data is missing from your request."}), 406

            # Get the variable containing the identity verification middleware globally used as `csrf_middleware`
            if self.headers.get("x-csrf_middleware", None):
                self.csrf_middleware = self.headers["x-csrf_middleware"]
            elif self.data.get("csrf_middleware", None):
                self.csrf_middleware = self.data["csrf_middleware"]
            elif self.headers.get("x-api_key", None):
                self.csrf_middleware = self.headers['x-api_key']
            elif self.data.get("api_key", None):
                self.csrf_middleware = self.data["api_key"]
            elif self.headers.get("x-authorization", None):
                self.csrf_middleware = self.headers['x-authorization']
            elif self.data.get("authorization", None):
                self.csrf_middleware = self.data["authorization"]

            await self.endpoint_validation()
            if self.return_exception is not None:
                return self.return_exception
        else:
            pass

    async def after_request(self, response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = self.allowed_methods
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['strict-transport-security'] = 'max-age=63072000; includeSubdomains'
        response.headers['x-frame-options'] = 'SAMEORIGIN'
        response.headers['x-xss-protection'] = '1; mode=block'
        response.headers['x-content-type-options'] = 'nosniff'
        response.headers['referrer-policy'] = 'origin-when-cross-origin'
        response.headers['Server'] = "Scarface"
        return response
    
    async def register_middleware(self):
        self.app.before_request(self.before_request)
        self.app.after_request(self.after_request)

class Components:
    def __init__(self, app) -> None:
        self.app = app

    async def get_request_data(self):
        req_type = request.method
        try:
            if req_type == "GET":
                headers = request.headers
                data = request.args

            elif req_type == "POST":
                data = await request.get_json()
                headers = request.headers
            else:
                data = False
                headers = False

            return data, headers
        except Exception as e:
            p(e)
            return False

class Setup:
    def __init__(self) -> None:
        self.app = Quart(__name__)
        self.comps = Components(self.app)
        self.middleware = Middleware(self.app, self.comps)
        self.app.config['UPLOAD_FOLDER'] = None
        self.app.config['MAX_CONTENT_LENGTH'] = 500000 * 1024 * 1024
        self.app.config['REQUEST_TIMEOUT'] = 500000
        self.app.config['QUART_SERVER'] = 'hypercorn'  # Use Hypercorn as the server
        self.app.config['HYPERCORN'] = {
            'keep_alive_timeout': 500000,
            'use_reloader': True
        }

    async def set_app(self):
        set_ = await self.middleware.register_middleware()
        if set_:
            return self.app, self.comps, self.middleware
    
    def main(self):
        asyncrun(self.set_app())
        return self.app, self.comps, self.middleware

setup = Setup()

class Elements:
    def __init__(self, setup):
        self.app, self.comps, self.middleware = setup.main()
    
    async def set_elements(self):
        return self.app, self.comps, self.middleware

elements = Elements(setup)

class Frontend:
    def __init__(self, elements):
        self.app = elements.app
        self.comps = elements.comps
        self.elements = elements
        self.secure_identity_items = [True, False][1]

    async def serve_static(self, path):
        try:
            return await send_file(self.elements.middleware.protect.static_dir + path)
        except PermissionError as e:
            p(f"Permission error: {e}")
            data = "Ohh no, you're onto something!"
        except FileNotFoundError:
            data = "Not found!"
        except Exception as e:
            p(f"Unexpected error: {e}")
            data = "Not found!"

        return jsonify({'error': data}), 404

    async def secure_data(self, secure_state, identity_data, secure_dict=None):
        new_identity_data = {}

        if not secure_dict:
            for key, value in identity_data.items():
                if isinstance(value, (str)):
                    encrypted_value = await safe.tool(value, secure_state)
                    new_identity_data[key] = encrypted_value
                else:
                    new_identity_data[key] = value
            identity_data = new_identity_data
        else:
            for key, value in identity_data[secure_dict].items():
                if isinstance(value, (str)):
                    encrypted_value = await safe.tool(value, secure_state)
                    new_identity_data[key] = encrypted_value
                else:
                    new_identity_data[key] = value
            identity_data[secure_dict] = new_identity_data
        return identity_data

    async def gen_token(self, user_data=None):
        try:
            ip = str(request.headers.get("X-Forwarded-For", "127.0.0.1"))
            if ip != "127.0.0.1":
                identifyer = ip
            else:
                identifyer = str(request.headers.get("User-Agent", "User-Agent"))
                
            identity_data = {"ip": ip, "token_gen_at": str(dt.now().time())}

            try:
                if self.secure_identity_items:
                    identity_data = await self.secure_data('encrypt', identity_data)

                create_user = await user_db.user_management(identifyer, "create_user", identity_data)
                if create_user[0] is not None:
                    return create_user[1]
                else:
                    get_user = await user_db.user_management(identifyer, "get_user")
                    self.session = {"session_time": str(dt.now().time()), "session_ip": ip, "activity": f"Visited {self.path}"}

                    if get_user[0]:
                        if self.secure_identity_items:
                            identity_data = await self.secure_data('decrypt', get_user[1])
                        else:
                            identity_data = get_user[1]
                        
                        if identity_data:
                            if self.secure_identity_items:
                                self.session = await self.secure_data('encrypt', self.session)
                            
                            if not identity_data.get("identity_sessions", False):
                                identity_data.update({"identity_sessions": [self.session]})
                            else:
                                identity_data["identity_sessions"].append(self.session)

                        if self.secure_identity_items:
                            identity_data = await self.secure_data('encrypt', identity_data)
                        await user_db.user_management(ip, "update_user", identity_data)

                    return create_user[1]

            except Exception as e:
                await logger.log_data(e)
                return jsonify({'error': "Something went wrong"}), 500

        except Exception as e:
            p(e)
            return False

    async def serve_pages(self, path="page/404"):
        path = str(path)
        self.path = path
        
        if not "page/" in path:
            return jsonify({'error': "The route specified doesn't match the style of our routes."}), 406
        path = path.split("page/")[1]

        while True:
            page_file = f'{self.elements.middleware.protect.static_dir}page/{path}.html'
            if not exists(page_file):
                path = "404"
            else:
                break

        try:
            with open(page_file, 'r') as file:
                html_content = file.read()
            try:
                token = await self.gen_token()
                csrf_middleware = await self.elements.middleware.protect.session_manager(token, "gen")
                html_content = html_content.replace('{{csrf_middleware}}', csrf_middleware)

            except Exception as e:
                await logger.log_data(e)
                return jsonify({'error': "Something went wrong"}), 500
            
        except Exception as e:
            await logger.log_data(e)
            return jsonify({'error': "Something went wrong"}), 500
        
        response = await make_response(html_content)
        return response

    def register_routes(self):
        self.app.add_url_rule('/app_data/<path:path>', 'serve_static', self.serve_static)
        self.app.add_url_rule('/<path:path>', 'serve_pages', self.serve_pages)

frontend = Frontend(elements)

if not exists(elements.middleware.protect.db_dir):
    mkdir(elements.middleware.protect.db_dir)
if not exists(elements.middleware.protect.users):
    mkdir(elements.middleware.protect.users)

if __name__ == '__main__':
    pass