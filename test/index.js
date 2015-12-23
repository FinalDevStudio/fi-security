'use strict';

var session = require('express-session');
var bodyParser = require('body-parser');
var request = require('request');
var express = require('express');
var expect = require('chai').expect;
var security = require('../lib');
var base64url = require('base64url');
var crypto = require('crypto');

var csrfToken = null;

/* The Security component configuration */
var config = {

  debug: true,

  p3p: 'ABCDEF',

  csrf: {
    exclude: [{
      path: '/no-csrf'
    }]
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
  }

};

describe('Fi Security', function () {
  before(function (done) {
    /* Create the express app */
    var app = express();

    /* Body parser first */
    app.use(bodyParser.urlencoded({
      extended: false
    }));

    app.use(bodyParser.json());

    /* Initialize the session before anything else */
    app.use(session({
      secret: base64url(crypto.randomBytes(48)),
      saveUninitialized: true,
      resave: true,
      cookie: {
        secure: false
      }
    }));

    /* Initialize the Security component before any route declaration */
    security(app, config);

    /* Now declare the routes */
    app.get('/', function (req, res) {
      res.send(res.locals._csrf);
    });

    app.post('/', function (req, res) {
      res.status(204).end();
    });

    app.post('/no-csrf', function (req, res) {
      res.status(204).end();
    });

    /* Error handler */
    app.use(function (err, req, res, next) {
      console.log("\n");
      console.error("   ", err);
      console.log("");
      res.end();
    });

    var server = app.listen(0, function () {
      /* Initialize the request object */
      request = request.defaults({
        baseUrl: 'http://localhost:' + server.address().port,
        jar: true
      });

      done();
    });
  });

  describe('object', function () {
    it('should be a function', function () {
      expect(security).to.be.a('function');
    });
  });

  describe('server', function () {

    it('should respond a 200 status code and "Hello Word!" as body', function (done) {
      request('/', function (err, res, body) {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(200);

        expect(body).to.be.a('string');

        csrfToken = body;

        done();
      });
    });
  });

  describe('requests', function () {
    it('should respond with a 403 status code when a POST to "/" is made without a CSRF token', function (done) {

      request.post('/', function (err, res, body) {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(403);

        done();
      });
    });

    it('should respond with a 204 status code when a POST to "/" is made with a CSRF token as form data', function (done) {
      request.post({
        uri: '/',
        form: {
          _csrf: csrfToken
        }
      }, function (err, res, body) {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(204);

        done();
      });
    });

    it('should respond with a 204 status code when a POST to "/" is made with a CSRF token as header param', function (done) {
      request.post({
        uri: '/',
        headers: {
          'x-csrf-token': csrfToken
        }
      }, function (err, res, body) {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(204);

        done();
      });
    });

    it('should respond with a 204 status code when a POST to "/no-csrf" is made without a CSRF token', function (done) {
      request.post('/no-csrf', function (err, res, body) {
        expect(err).to.be.null;

        expect(res.statusCode).to.be.a('number');
        expect(res.statusCode).to.equal(204);

        done();
      });
    });
  });

});
