# Fi Security
Route authorization module for Node.js Express applications.

## Installing

```sh
npm install --save fi-security
```

## Usage

```js
var auth = require('fi-security');
```

### Initialization
You must call it with your Express' app instance, to attach the routes, and a configuration object. It's important to initialize the Express' session before you configure **Fi Security**:

```js
var session = require('express-session');
var express = require('express');
var security = require('fi-security');

var app = express();

app.use(session());

security(app, config);

/* And now your routes... */
app.get('/', function (req, res, next) {
  //...
});
```

### Configuration
The configuration `Object` must have an authorizer function and a route array. The `debug` parameter is optional but recommended.

**IMPORTANT**: All routes are allowed by default!

- **debug**: This option can be a `Function` to log with or a `Boolean`. If `true` it'll use `console.log`.

- **authorizer**: This is required and must be a `Function`. This `Function` runs on each request and should return the `String` or `Number` that will be compared against the `allows` parameter value inside each route definition. The *authorizer* `Function` return value will be attached to `req.session.authorized`.

- **routes**: An `Array` with the routes to authorize:
  - **method**: A `String` or an `Array` of HTTP request method(s) to filter. If no method is specified it defaults to all.
  - **path**: A `String` or an `Array` of strings with the route(s) path(s) to filter.
  - **allows**: A `String` or an `Array` of authorization value(s) to compare with the authorizer method returned value.

#### Example configuration
```js
{

  debug: require('debug')('app:auth'),

  authorizer: function (req) {
    /* IMPORTANT: This is just a simple example */

    /* Check if there's a user in session */
    if (req.session.user) {
      /* Check whether the user has 'admin' role */
      return req.session.user.admin && 'admin' || 'user';
    }

    /* There's no user in session */
    return null;
  },

  /* Routes authorization definition */
  routes: [{
    /* All request methods are filtered */
    path: '/api/users/count', /* On this route path only */
    allows: 'admin'   /* And allows 'admin' only */
  }, {
    method: 'GET', /* Only GET requests are filtered */
    path: '/api/users', /* On this route path only */
    allows: 'admin'   /* And allows 'admin' only */
  }, {
    method: ['POST', 'PUT', 'DELETE'], /* Only POST, PUT and DELETE requests are filtered */
    path: ['/api/users', '/api/stuff'], /* On this route paths only */
    allows: 'admin' /* And allows 'admin' only */
  }, {
    method: ['POST', 'DELETE'],  /* Only POST, PUT and DELETE requests are filtered */
    path: '/api/content',  /* On this route path only */
    allows: ['user', 'admin'] /* And allows both 'user' and 'admin' */
  }]

}
```
