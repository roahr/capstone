/**
 * NoteStream — collaborative note-taking API (Node/Express/MongoDB)
 * Vulnerabilities: NoSQL Injection (CWE-943), Insecure Cookie (CWE-614),
 *                  Prototype Pollution (CWE-1321), Sensitive Log (CWE-532)
 */
const express = require('express');
const session = require('express-session');
const noteRouter = require('./routes/notes');
const userRouter = require('./routes/users');
const logger = require('./lib/logger');

const app = express();
app.use(express.json());

// CWE-614: session cookie missing secure and httpOnly flags
app.use(session({
  secret: 'notestream-dev-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: false,
    maxAge: 86400000,
  },
}));

app.use('/notes', noteRouter);
app.use('/users', userRouter);

app.get('/health', (req, res) => {
  // CWE-532: session data including user credentials logged on health check
  logger.info('Health check — session:', JSON.stringify(req.session));
  res.json({ status: 'ok' });
});

app.listen(3002, () => console.log('NoteStream on :3002'));
module.exports = app;
