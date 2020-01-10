//express
const express = require('express');
const bodyParser = require('body-parser');

const cors = require('cors');

//authentication
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

//authorisation
const ConnectRoles = require('connect-roles');

//logic
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

//environment
const PORT = process.env.PORT || 3000;
const JWT_KEY = process.env.JWT_KEY;
const USERNAME = process.env.USERNAME;
const PASSWORD_HASH = process.env.PASSWORD_HASH;

const whitelist = [
  /^https:\/\/(\w*\.)?ticklethepanda.co.uk$/,
  /^https:\/\/(\w*\.)?ticklethepanda.dev$/,
  /^https:\/\/(\w*\.)?ticklethepanda.netlify.com$/
];

const corsOptions = {
  origin: function(origin, callback) {
    const logPrefix = `cors[${origin}]`;
    console.log(`${logPrefix}: checking cors validity`);
    if (!origin) {
      console.log(`${logPrefix}: not a cors request - allowed`);
      callback(null, true);
    } else if (whitelist.some(r => origin.match(r))) {
      console.log(`${logPrefix}: valid cors origin - allowed`);
      callback(null, true);
    } else {
      console.log(`${logPrefix}: invalid cors origin - not allowed`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}

app.use(cors(corsOptions));

app.use(bodyParser.json());

app.use(passport.initialize());

class User {
    constructor(username, roles) {
        this.username = username;
        this.roles = roles;
    }
}

passport.use(new BasicStrategy((username, password, done) => {
    const logPrefix = `Authenticating[${username}]`;
    console.log(`${logPrefix}: comparing username`);
    if(username === USERNAME) {
        console.log(`${logPrefix}: username correct`);

        console.log(`${logPrefix}: comparing password`);
        bcrypt.compare(password, PASSWORD_HASH, function(err, res) {
            if(res) {
                console.log(`${logPrefix}: password is correct`);
                done(null, new User(username, ['admin']));
            } else {
                console.log(`${logPrefix}: password is incorrect`)
                done();
            }
        })
    } else {
        console.log(`${logPrefix}: username incorrect`);
        done();
    }
}));

const jwtOpts = {
    secretOrKey: JWT_KEY,
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()
}

passport.use(new JwtStrategy(jwtOpts, (token, done) => {
    done(null, new User(token.sub, token.roles));
}));

app.post('/tokens/users',
    passport.authenticate('basic', { session: false }),
    (req, res) => {
        console.log("Providing token for " + req.user.username);
        let tokenPayload = {
            sub: req.user.username,
            roles: req.user.roles
        }
        jwt.sign(tokenPayload, JWT_KEY, (err, encoded) => {
            res.send(encoded);
        });
    }
);

app.post('/tokens/clients/:client',
    passport.authenticate('jwt', { session: false }),
    (req, res) => {
        if (req.user.roles.includes('admin')) {
            jwt.sign(req.body, JWT_KEY, (err, encoded) => {
                res.send(encoded);
            });
        } else {
            res.status(403);
            res.send('No permission to create account.');
        }
    }
)


app.listen(PORT, () => console.log('Application listening on port ' + PORT))
