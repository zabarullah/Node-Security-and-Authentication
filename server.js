const fs = require('fs');  //  fs (file system) module to access key and cert files
const path = require('path');  //  path module to locate index.html
const https = require('https');  //  https module for secure server communication
const express = require('express');  //  express module for creating an express application
const helmet = require('helmet');  //  helmet module for secure HTTP headers
const passport = require('passport');  //  passport module for authentication
const { Strategy } = require('passport-google-oauth20');  //  Google OAuth strategy from the passport-google-oauth20 module
const cookieSession = require('cookie-session');  //  cookie-session module to manage session data as cookies
const { verify } = require('crypto');  //  crypto module for secure data verification

require('dotenv').config();  // load environment variables from .env file

const PORT = 3000;  // set the port for the server to listen on

const config = {
  CLIENT_ID: process.env.CLIENT_ID,  // get the client ID from environment variables
  CLIENT_SECRET: process.env.CLIENT_SECRET,  // get the client secret from environment variables
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,  // get the first cookie key from environment variables
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,  // get the second cookie key from environment variables
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',  // set the callback URL for Google OAuth
  clientID: config.CLIENT_ID,  // set the client ID from config
  clientSecret: config.CLIENT_SECRET,  // set the client secret from config
};

// callback function to verify the user profile
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);  // log the user profile 
  done(null, profile);  // pass the user profile to the next step of the authentication process
}

// use the Google OAuth strategy with the AUTH_OPTIONS and verifyCallback
passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// save the user ID(session) to the cookie
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// read the user ID(session) from the cookie
passport.deserializeUser((id, done) => {
  // User.findById(id).then(user => {
  //   done(null, user);
  // });
  done(null, id);
});

const app = express();  // create an express application

app.use(helmet());  // use the helmet middleware to set secure HTTP headers

// Use cookie-session to store the user session
app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000,
  keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ],
}));

// Initialize passport and the session
app.use(passport.initialize());
app.use(passport.session());

// Middleware function to check if the user is logged in
function checkLoggedIn(req, res, next) { 
  console.log('Current user is:', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must log in!',
    });
  }
  next();
}

// Route for initiating the authentication process with Google
app.get('/auth/google', 
  passport.authenticate('google', {
    scope: ['email'],
  }));

// Handle the response from Google after authentication
app.get('/auth/google/callback', 
  passport.authenticate('google', {
    failureRedirect: '/failure',    // If authentication fails, redirect to /failure
    successRedirect: '/',           // If authentication is successful, redirect to the root
    session: true,                  // Start a new session
  }), 
  (req, res) => {
    console.log('Google called us back!');
  }
);

// Log out the user by removing the req.user property and clearing the session
app.get('/auth/logout', (req, res) => {
  req.logout();                 //Removes req.user and clears any logged in session
  return res.redirect('/');     // redirect to the root endpoint
});

// Send a message with the personal secret value to the user if they are authenticated
app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Your personal secret value is 42!');
});

// Return a message indicating that the login has failed
app.get('/failure', (req, res) => {
  return res.send('Failed to log in!');
});

// Serves the index.html file from the public directory
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create an HTTPS server and listen on port 3000
https.createServer({
  key: fs.readFileSync('key.pem'),        // Load the SSL key file
  cert: fs.readFileSync('cert.pem'),      // Load the SSL certificate file
}, app).listen(PORT, () => {
  console.log(`Listening on port ${PORT}...`);
});