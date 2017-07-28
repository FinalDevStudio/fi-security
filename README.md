# Fi Security

Application security module for Node.js Express applications.

## Installing

```sh
npm install --save fi-security
```

## Usage

### Initialization

You must call it with your Express' application instance, to attach the routes, and a configuration object. It's important to initialize the Express' session before you configure **Fi Security**:

```js
var session = require('express-session');
var security = require('fi-security');
var express = require('express');

var app = express();

app.use(session());

security(app, config);

/* And now your routes... */
app.get('/', (req, res, next) => {
  //...
});
```

### Configuration

The configuration `Object` must be pretty much like a [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#api) configuration `Object`, since this module is based on it.

- **debug**: This option can be a `Function` to log with or a `Boolean`. If `true` it'll use `console.log`.
- **csrf**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#cross-site-request-forgery) with the addition of the `exclude` property:
  - **exclude**: An array of routes with their method(s) and path(s) to be excluded from `CSRF` checks:
    - **method**: A single `POST`, `PUT` or `DELETE` method or an array of them. Empty means `ALL`.
    - **path**: A valid [Express route path](http://expressjs.com/en/guide/routing.html#route-paths).
- **csp**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#content-security-policy).
- **xframe**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#x-frame-options).
- **hsts**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#http-strict-transport-security).
- **nosniff**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#x-content-type-options).
- **xssProtection**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#x-xss-protection).
- **p3p**: Same as [Fi Aegis](https://github.com/FinalDevStudio/fi-aegis#platform-for-privacy-preferences-p3p-project).

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
  },

  nosniff: true
}
```

### Using with AngularJS

Just add this to your **Fi Security** configuration:

```js
//...

csrf: {
  angular: true
  //...
}

//...
```

See [this](https://docs.angularjs.org/api/ng/service/$http#cross-site-request-forgery-xsrf-protection) for more information regarding AngularJS' XSRF approach.
