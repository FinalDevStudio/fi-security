'use strict';

var lusca = require('lusca');
var is = require('is_js');

var debug = function () {};

var GET_RE = /.*(get).*/gi;
var POST_RE = /.*(post).*/gi;
var PUT_RE = /.*(put).*/gi;
var DELETE_RE = /.*(delete).*/gi;
var $1 = '$1';

/**
 * Returns a clean, lower-case method name.
 *
 * @param {String} method - The method to check and clean.
 *
 * @return {String}
 */
function clean(method) {
  if (method.match(GET_RE)) {
    return method.replace(GET_RE, $1).toLowerCase();
  }

  if (method.match(POST_RE)) {
    return method.replace(POST_RE, $1).toLowerCase();
  }

  if (method.match(PUT_RE)) {
    return method.replace(PUT_RE, $1).toLowerCase();
  }

  if (method.match(DELETE_RE)) {
    return method.replace(DELETE_RE, $1).toLowerCase();
  }

  throw new Error("Invalid method [" + method + "]!");
}

/**
 * Default exclusion middleware.
 *
 * @type {ExpressMiddlware}
 */
function middleware(req, res, next) {
  req.security.csrf.exclude = true;
  next();
}

/**
 * Generates the Express middleware to associate the allowed values to the route.
 *
 * @param {ExpressRouter} router - The generated Express router object.
 * @param {String} method -  The method to exclude.
 */
function exclude(router, method) {
  router[method](middleware);
}

/**
 * Normalizes a route object.
 *
 * @param {Object} route - The route object to normalize.
 *
 * @return {Object}
 */
function normalize(route) {
  if (is.not.array(route.path) && is.not.string(route.path)) {
    throw new Error("The route's path must be a [String] or an [Array] of [String]s!");
  }

  if (is.array(route.method)) {
    /* If method is an array */
    route.method.forEach(function (method, index) {
      route.method[index] = clean(method);
    });
  }

  /* If method is a string */
  if (is.string(route.method)) {
    route.method = clean(route.method);
  }

  return route;
}

/**
 * Processes each excluded route.
 *
 * @param {ExpressApplication} app - Your express application instance.
 * @param {Object} route - The route object to process.
 */
function onEachExcludedRoute(app, route) {
  route = normalize(route);

  debug("Excluding " + (route.method || 'all').toUpperCase() + " " + route.path + " from CSRF check...");

  var router = app.route(route.path);

  if (is.array(route.method) && route.method.length) {
    return route.method.forEach(function (method) {
      exclude(router, method);
    });
  }

  if (is.string(route.method)) {
    return exclude(router, route.method);
  }

  /* Defaults to all */
  exclude(router, 'all');
}

module.exports = function (app, config) {
  /* Check debug type */
  if (is.function(config.debug)) {
    debug = config.debug;
  } else if (config.debug) {
    debug = console.log;
  }

  /* CSRF */
  if (config.csrf) {
    debug("Configuring Cross-Site Request Forgery protection...");

    /* Default to include all routes on CSRF check */
    app.use(function (req, res, next) {
      req.security = {
        csrf: {
          exclude: false
        }
      };

      next();
    });

    /* Check if exclude is set on the options */
    if (is.object(config.csrf) && config.csrf.exclude) {
      config.csrf.exclude.forEach(function (route) {
        onEachExcludedRoute(app, route);
      });
    }

    /* Ensure that no extra parameters are passed to lusca's CSRF module */
    delete config.csrf.exclude;

    /* Generate CSRF middleware */
    var csrf = lusca.csrf(config.csrf);

    /* Middleware to check if CSRF check should be performed */
    app.use(function (req, res, next) {
      if (req.security.csrf.exclude) {
        return next();
      }

      csrf(req, res, next);
    });
  }

  /* P3P */
  if (is.string(config.p3p)) {
    debug("Configuring Platform for Privacy Preferences...");
    app.use(lusca.p3p(config.p3p));
  }

  /* CSP */
  if (is.object(config.csp)) {
    debug("Configuring Content Security Policy...");
    app.use(lusca.csp(config.csp));
  }

  /* X-FRAME */
  if (is.string(config.xframe)) {
    debug("Configuring X-Frame-Options response header...");
    app.use(lusca.xframe(config.xframe));
  }

  /* HSTS */
  if (config.hsts) {
    debug("Configuring HTTP Strict Transport Security...");
    app.use(lusca.hsts(config.hsts));
  }

  /* XSS */
  if (config.xssProtection) {
    debug("Configuring Cross-site scripting protection...");
    app.use(lusca.xssProtection(config.xssProtection));
  }
};
