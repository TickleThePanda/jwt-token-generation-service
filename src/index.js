//express
const express = require('express');
const bodyParser = require('body-parser');

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

app.use(bodyParser.json());

app.use(passport.initialize());

class User {
    constructor(username, roles) {
        this.username = username;
        this.roles = roles;
    }
}

passport.use(new BasicStrategy((username, password, done) => {
    if(username === USERNAME) {
        bcrypt.compare(password, PASSWORD_HASH, function(err, res) {
            if(res) {
                done(null, new User(username, ['admin']));
            } else {
                done();
            }
        })
    } else {
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
