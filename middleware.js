const csrf = require('csurf');

const csrfProtection = csrf({
  cookie: false,
  value: (req) => req.body._csrf || req.headers['x-csrf-token']
});

const validateSession = (req, res, next) => {
  if (!req.session.username) {
    return res.status(403).send('Unauthorized');
  }
  next();
};

module.exports = { csrfProtection, validateSession };