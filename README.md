# Scarface

**Scarface** is an asynchronous web framework built on top of Quart, designed to implement custom security, performance, and efficiency in deploying Python applications.

## Features

- **Asynchronous Operations:** Leveraging Quart for asynchronous capabilities.
- **Custom Security:** Includes encryption/decryption with Fernet, HMAC hashing, JWT token generation, and CSRF protection.
- **User Management:** Secure user database management with encrypted storage.
- **Rate Limiting:** Implementing rate limits to protect against abuse.
- **Middleware:** Custom middleware for request validation and processing.
- **Static File Serving:** Efficient handling of static files and dynamic page rendering.

## Installation

To install Scarface, run the following command:

```bash
pip install git+https://github.com/anonyxbiz/Scarface
```

## Quick Start

Here is a simple example to get you started with Scarface:

```python
# main.py
from Scarface import jsonify, frontend, elements, request, logger, token_urlsafe, dt, make_response, safe, user_db
from hypercorn.asyncio import serve
from hypercorn.config import Config
from asyncio import run as asyncrun

app, comps, middleware = elements.app, elements.comps, elements.middleware
frontend.register_routes()

middleware.protected_routes = ["/user/", "/app/"]
middleware.allowed_methods = 'GET, POST'
middleware.protect.allowed_hosts = ["127.0.0.1:8001", "localhost:8001"]
elements.middleware.protect.protect_data = False
frontend.secure_identity_items = False

# Serve homepage
@app.route('/', methods=['GET', 'POST'])
async def index():
    # Create a static dir and inside it, add static folders css, js and page then inside page add your index.html
    # Add /app_data/ before the path of the file you want to access in the ./static dir:
    """
    images = /app_data/images/favicon.png
    css = /app_data/css/test.css
    javascript = /app_data/js/index.js
    """
    # You should include <meta name="csrf_middleware" content="{{csrf_middleware}}"> in templates you want to get the csrf_middleware added for you.

    # So an example of how your ./static/page/index.html file should be
    """
    <!DOCTYPE html>
    <html lang="en" dir="ltr">

    <head>
        <meta charset="utf-8">
        <title>Scarface | Index</title>
        <link rel="stylesheet" href="/app_data/css/test.css">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="csrf_middleware" content="{{csrf_middleware}}">
        <link rel="icon" type="image/png" href="/app_data/images/favicon.png">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200" />
    </head>

    <body>
        <script src="/app_data/js/index.js"></script>
    </body>
    </html>

    """

    response = await frontend.serve_pages('page/index')
    if response:
        return response

# Serve a rest api
@app.route('/app/models/test', methods=['GET', 'POST'])
async def spotify_data():
    data, headers = await comps.get_request_data()
    return jsonify({'detail': 'It works!'})

# Use hypercorn in production
async def production(host, port, debug, keep_alive_timeout, use_reloader):
    config = Config()
    config.bind = [f"{host}:{port}"]
    config.keep_alive_timeout = keep_alive_timeout
    config.use_reloader = use_reloader
    await serve(app, config)

if __name__ == '__main__':
    host, port, debug, keep_alive_timeout, use_reloader = "0.0.0.0", int(middleware.protect.allowed_hosts[0].split(":")[1]), False, 36000, True
    state = ["Development", "Production"]

    if state[0] == "Development":
        app.run(host, port, debug)
    else:
        asyncrun(production(host, port, debug, keep_alive_timeout, use_reloader))
```

## Usage

### Setting Up the Environment

Scarface relies on environment variables for certain configurations. Make sure to set the `safe_key` environment variable for encryption:

```bash
export safe_key="your_safe_key_here"
```

### Middleware

Scarface provides built-in middleware for request validation, CSRF protection, and rate limiting.

### User Management

Manage users securely with encryption:

```python
from Scarface import user_db

# Create a new user
user_identifier = "user@example.com"
user_data = {"name": "Example User"}
create_user = await user_db.user_management(user_identifier, "create_user", user_data)

# Get a user
get_user = await user_db.user_management(user_identifier, "get_user")
```

### Logging

Scarface includes simple logging functionality:

```python
from Scarface import logger

await logger.log_data("This is a log message")
```

### Encryption and Decryption

Use the `Safe` class for encrypting and decrypting data:

```python
from Scarface import safe

# Encrypt data
encrypted_data = await safe.tool("your_data_here", "encrypt")

# Decrypt data
decrypted_data = await safe.tool(encrypted_data, "decrypt")
```

## Contributing

Feel free to contribute to Scarface by creating issues or submitting pull requests. Your contributions are greatly appreciated!

## License

MIT License

```
MIT License

Copyright (c) 2024 Anonyxbiz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```