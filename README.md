# Fi Security
Route authorization module for Node.js Express applications.

## Installing

```sh
npm install --save fi-security
```

## Usage
### Initialization
You must call it with your Express' application instance, to attach the routes, and a configuration object. It's important to initialize the Express' session before you configure **Fi Security**:

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
The configuration `Object` must be pretty much like a [lusca](https://github.com/krakenjs/lusca#api) configuration `Object`, since this module is based on it.
- **debug**: This option can be a `Function` to log with or a `Boolean`. If `true` it'll use `console.log`.
- **csrf**: Same as [lusca](https://github.com/krakenjs/lusca#luscacsrfoptions) with the addition of the `exclude` property:
  - **exclude**: An array of routes with it's method and path to be excluded from `CSRF` checks:
    - **method**: A single `POST`, `PUT` or `DELETE` method or an array of them. Empty means `ALL`.
    - **path**: A valid [Express path](http://expressjs.com/en/guide/routing.html#route-paths) to be excluded from the `CSRF` check.

- **csp**: Same as [lusca](https://github.com/krakenjs/lusca#luscacspoptions).
- **xframe**: Same as [lusca](https://github.com/krakenjs/lusca#luscaxframevalue).
- **p3p**: Same as [lusca](https://github.com/krakenjs/lusca#luscap3pvalue).
- **hsts**: Same as [lusca](https://github.com/krakenjs/lusca#luscahstsoptions).
- **xssProtection**: Same as [lusca](https://github.com/krakenjs/lusca#luscaxssprotectionoptions).

#### Example configuration

```js
{
  debug: true,

  p3p: 'ABCDEF',

  csrf: {
    exclude: [{
      method: 'POST',
      path: '/no-csrf'
    }, {
      path: '/api/external'
    }]
  },

  xframe: 'DENY',

  xssProtection: {
    enabled: true
  },

  csp: {
    reportUri: 'https://example.com',    
    policy: {
      'default-src': "'self'"
    }
  },

  hsts: {
    includeSubDomains: true,
    maxAge: 31536000
  }
}
```

### Using with AngularJS
It's a good idea to set the `csrf.header` option to `X-XSRF-TOKEN` and set a cookie named `XSRF-TOKEN` with the correct `CSRF` token generated by [lusca](https://github.com/krakenjs/lusca) on the first request to allow AngularJS to seamlessly attach the `CSRF` token on each request through the `$http` module.

To do so, add this to your **Fi Security** configuration:
```js
//...

csrf: {
  header: 'X-XSRF-TOKEN'
  //...
}

//...
```

And this to the root path of your Express application:
```js
app.get('/', function (req, res, next) {
  /* Lusca sets the CSRF token in res.locals._csrf */
  res.cookie('XSRF-TOKEN', res.locals._csrf);

  res.render('angular-layout');
});
```

See [this](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection) for more information regarding AngularJS' XSRF approach.
