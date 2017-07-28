'use strict';

const aegis = require('fi-aegis');
const is = require('fi-is');

const GET_RE = /.*(get).*/gi;
const POST_RE = /.*(post).*/gi;
const PUT_RE = /.*(put).*/gi;
const DELETE_RE = /.*(delete).*/gi;
const $1 = '$1';

var debug = function () {};

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

  throw new Error(`Invalid method [${ method }]!`);
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
    throw new Error('The route\'s path must be a [String] or an [Array] of [String]s!');
  }

  if (is.array(route.method)) {
    /* If method is an array */
    for (let i = 0, l = route.method.length; i < l; i++) {
      route.method[i] = clean(route.method[i]);
    }
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

  debug(`Excluding ${ (route.method || 'all').toUpperCase()} ${ route.path } from CSRF check...`);

  var router = app.route(route.path);

  if (is.array(route.method) && route.method.length) {
    for (let i = 0, l = route.method.length; i < l; i++) {
      exclude(router, route.method[i]);
    }
  }

  if (is.string(route.method)) {
    return exclude(router, route.method);
  }

  /* Defaults to all */
  exclude(router, 'all');
}

module.exports = (app, config) => {
  /* Check debug type */
  if (is.function(config.debug)) {
    debug = config.debug;
  } else if (config.debug) {
    debug = console.log;
  }

  /* CSRF */
  if (config.csrf) {
    debug('Configuring Cross-Site Request Forgery protection...');

    /* Default to include all routes on CSRF check */
    app.use((req, res, next) => {
      req.security = {
        csrf: {
          exclude: false
        }
      };

      next();
    });

    /* Check if exclude is set on the options */
    if (is.object(config.csrf) && config.csrf.exclude) {
      for (let i = 0, l = config.csrf.exclude.length; i < l; i++) {
        onEachExcludedRoute(app, config.csrf.exclude[i]);
      }
    }

    /* Ensure that no extra parameters are passed to Fi Aegis' CSRF module */
    delete config.csrf.exclude;

    /* Generate CSRF middleware */
    var csrf = aegis.csrf(config.csrf);

    /* Middleware to check if CSRF check should be performed */
    app.use((req, res, next) => {
      if (req.security.csrf.exclude) {
        return next();
      }

      csrf(req, res, next);
    });
  }

  /* P3P */
  if (is.string(config.p3p)) {
    debug('Configuring Platform for Privacy Preferences...');
    app.use(aegis.p3p(config.p3p));
  }

  /* CSP */
  if (is.object(config.csp)) {
    debug('Configuring Content Security Policy...');
    app.use(aegis.csp(config.csp));
  }

  /* X-FRAME */
  if (is.string(config.xframe)) {
    debug('Configuring X-Frame-Options response header...');
    app.use(aegis.xframe(config.xframe));
  }

  /* HSTS */
  if (config.hsts) {
    debug('Configuring HTTP Strict Transport Security...');
    app.use(aegis.hsts(config.hsts));
  }

  /* XSS */
  if (config.xssProtection) {
    debug('Configuring Cross-site scripting protection...');
    app.use(aegis.xssProtection(config.xssProtection));
  }

  /* Nosniff */
  if (config.nosniff) {
    debug('Configuring No Sniff header...');
    app.use(aegis.nosniff());
  }
};
