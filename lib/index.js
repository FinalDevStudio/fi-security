const aegis = require('fi-aegis');
const is = require('fi-is');

const methods = require('./methods');

let debug = () => { };

/**
 * Returns a clean, lower-case method name.
 *
 * @param {String} method The method to check and clean.
 *
 * @returns {String} The clean method name.
 */
function clean (method) {
  const _method = String(method).toLowerCase();

  if (!methods.includes(_method)) {
    throw new Error(`Invalid method name: ${method}`);
  }

  return _method;
}

/**
 * Default exclusion middleware.
 *
 * @type {ExpressMiddleware}
 *
 * @param {Object} req Express' request object.
 * @param {Object} res Express' response object.
 * @param {Function} next Express' next middleware callback.
 */
function middleware (req, res, next) {
  req.security.csrf.exclude = true;
  next();
}

/**
 * Generates the Express middleware to associate the allowed values to the route.
 *
 * @param {ExpressRouter} router - The generated Express router object.
 * @param {String} method -  The method to exclude.
 */
function exclude (router, method) {
  router[String(method)](middleware);
}

/**
 * Normalizes a route object.
 *
 * @param {Object} route The route object to normalize.
 *
 * @returns {Object} The normalized route object.
 */
function normalize (route) {
  const _route = { ...route };

  if (is.not.array(_route.path) && is.not.string(_route.path)) {
    throw new Error("The route's path must be a String or [String]");
  }

  if (is.array(_route.method)) {
    /* If method is an array */
    for (let method of _route.method) {
      method = clean(method);
    }
  }

  /* If method is a string */
  if (is.string(_route.method)) {
    _route.method = clean(_route.method);
  }

  return _route;
}

/**
 * Processes each excluded route.
 *
 * @param {ExpressApplication} app Your express application instance.
 * @param {Object} route The route object to process.
 */
function onEachExcludedRoute (app, route) {
  const _route = normalize(route);

  const router = app.route(_route.path);

  debug(`Excluding "${_route.method} ${_route.path}" from CSRF check...`);

  if (is.string(_route.method)) {
    exclude(router, _route.method);
    return;
  }

  if (is.array(_route.method)) {
    for (let method of _route.method) {
      exclude(router, method);
    }

    return;
  }

  debug(`Excluding "all ${_route.path}" from CSRF check...`);

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
      for (let exclude of config.csrf.exclude) {
        onEachExcludedRoute(app, exclude);
      }
    }

    /* Ensure that no extra parameters are passed to Fi Aegis' CSRF module */
    delete config.csrf.exclude;

    /* Generate CSRF middleware */
    const csrf = aegis.csrf(config.csrf);

    /* Middleware to check if CSRF check should be performed */
    app.use((req, res, next) => {
      if (req.security.csrf.exclude) {
        next();
        return;
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
