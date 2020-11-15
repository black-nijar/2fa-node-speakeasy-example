const express = require('express');
const speakeasy = require('speakeasy');
const uuid = require('uuid');
const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig');
const { json } = require('express');

const app = express();
app.use(express.json());

const db = new JsonDB(new Config('myDatabase', true, false, '/ '));

app.get(`/api`, (req, res) => {
  res.json({
    message: 'Welcom to 2 factor Authentication',
  });
});

// Reg user & create temp secret
app.post('/api/register', (req, res) => {
  const id = uuid.v4();
  try {
    const path = `/user/${id}`;
    const tempSecret = speakeasy.generateSecret();
    db.push(path, { id, tempSecret });
    res.json({ id, secret: tempSecret.base32 });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: 'Error generating the secret',
    });
  }
});

// verify token and secret perm
app.post('/api/verify', (req, res) => {
  const { token, userId } = req.body;

  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);

    const { base32: secret } = user.tempSecret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
    });
    if (verified) {
      db.push(path, { id: userId, secret: user.tempSecret });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: 'Error finding user',
    });
  }
});

// validate token
app.post('/api/validate', (req, res) => {
  const { token, userId } = req.body;

  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);

    const { base32: secret } = user.secret;
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 1,
    });
    if (tokenValidates) {
      res.json({ validated: true });
    } else {
      res.json({ validated: false });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: 'Error finding user',
    });
  }
});

const PORT = process.env.PORT || 6000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
