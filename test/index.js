const session = require('express-session');
const bodyParser = require('body-parser');
const base64url = require('base64url');
const { expect } = require('chai');
const request = require('request');
const express = require('express');
const crypto = require('crypto');

const security = require('../lib');

/* The Security component configuration */
const config = {
  debug: false,

  p3p: 'ABCDEF',

  csrf: {
    exclude: [
      {
        path: '/no-csrf'
      },
      {
        path: ['/no-csrf', '/another']
      },
      {
        path: ['/no-csrf', '/another'],
        method: 'get'
      },
      {
        path: ['/no-csrf', '/another'],
        method: ['get', 'post']
      }
    ]
  },

  xframe: 'DENY',

  xssProtection: {
    enabled: true
  },

  csp: {
    policy: {
      'default-src': "'self'"
    }
  },

  hsts: {
    includeSubDomains: true,
    maxAge: 31536000
  },

  nosniff: true
};

describe('Fi Security', function () {
  let $server, $http, $token;

  before(async function () {
    /* Create the express app */
    const app = express();

    /* Body parser first */
    app.use(bodyParser.urlencoded({
      extended: false
    }));

    app.use(bodyParser.json());

    /* Initialize the session before anything else */
    app.use(session({
      secret: base64url(crypto.randomBytes(16)),
      saveUninitialized: true,
      resave: true,
      cookie: {
        secure: false
      }
    }));

    /* Initialize the Security component before any route declaration */
    security(app, config);

    /* Now declare the routes */
    app.get('/', (req, res) => {
      res.send(res.locals._csrf);
    });

    app.post('/', (req, res) => {
      res.sendStatus(204);
    });

    app.post('/no-csrf', (req, res) => {
      res.sendStatus(204);
    });

    /* Error handler */
    app.use((err, req, res, next) => {
      res.end();
    });

    await new Promise(resolve => {
      $server = app.listen(0, () => {
        /* Initialize the request object */
        $http = request.defaults({
          baseUrl: `http://localhost:${$server.address().port}`,
          jar: true
        });

        resolve();
      });
    });
  });

  after(async function () {
    if ($server) {
      await $server.close();
    }
  });

  describe('object', function () {
    it('should be a function', function () {
      expect(security).to.be.a('function');
    });

    it('should initialize with debug as true', function () {
      const app = express();
      const cfg = {
        ...config,
        debug: true
      };

      expect(() => security(app, cfg)).to.not.throw();
    });

    it('should initialize with debug as a function', function () {
      const app = express();
      const cfg = {
        ...config,
        debug: msg => console.log(`[TEST] ${msg}`)
      };

      expect(() => security(app, cfg)).to.not.throw();
    });

    it('should not initialize with invalid method names', function () {
      const app = express();
      const cfg = {
        ...config,
        debug: false,
        csrf: {
          exclude: [{
            method: 'lol',
            path: '/'
          }]
        }
      };

      expect(() => security(app, cfg)).to.throw();
    });

    it('should not initialize with invalid exclude definition', function () {
      const app = express();
      const cfg = {
        ...config,
        debug: false,
        csrf: {
          exclude: [{
            method: 'get'
          }]
        }
      };

      expect(() => security(app, cfg)).to.throw();
    });
  });

  describe('server', function () {
    it('should respond a 200 status code and "Hello Word!" as body', function (done) {
      $http.get('/', (err, res, body) => {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(200);

        expect(body).to.be.a('string');

        $token = body;

        done();
      });
    });
  });

  describe('requests', function () {
    it('should respond with a 403 status code when a POST to "/" is made without a CSRF token', function (done) {
      $http.post('/', (err, res) => {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(403);

        done();
      });
    });

    it('should respond with a 204 status code when a POST to "/" is made with a CSRF token as form data', function (done) {
      $http.post(
        {
          uri: '/',
          form: {
            _csrf: $token
          }
        },
        (err, res) => {
          expect(err).to.be.null;

          expect(res.statusCode).to.be.a('number');
          expect(res.statusCode).to.equal(204);

          done();
        }
      );
    });

    it('should respond with a 204 status code when a POST to "/" is made with a CSRF token as header param', function (done) {
      $http.post(
        {
          uri: '/',
          headers: {
            'csrf-token': $token
          }
        },
        (err, res) => {
          expect(err).to.be.null;

          expect(res.statusCode).to.be.a('number');
          expect(res.statusCode).to.equal(204);

          done();
        }
      );
    });

    it('should respond with a 204 status code when a POST to "/no-csrf" is made without a CSRF token', function (done) {
      $http.post('/no-csrf', (err, res) => {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(204);

        done();
      });
    });
  });
});
