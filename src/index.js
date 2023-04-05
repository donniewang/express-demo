// init project
var express = require("express");
var low = require("lowdb");
var FileSync = require("lowdb/adapters/FileSync");
var path = require("path");
// Data is stored in the file `database.json` in the folder `db`.
// Note that if you leave your app public, this database file will be copied if
// someone forks your app. So don't use it to store sensitive information.
var adapter = new FileSync("./db/database.json");
var db = low(adapter);
var app = express();
// var bodyParser = require("body-parser");
const srcPath = __dirname;
// Using `public` for static files: http://expressjs.com/en/starter/static-files.html
app.use(express.static(path.join(srcPath, "public")));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

const cors = require("cors");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "JWT_SECRET";

app.use(cors());

const bcrypt = require("bcrypt");
const saltRounds = 10;
const salt = bcrypt.genSaltSync(saltRounds);

app.get("/api/auth/signin", async (req, res) => {
  const { username, password } = req.query;

  if (!!!username) {
    return res.json({ error: "username is required" });
  }
  if (!!!password) {
    return res.json({ error: "password is required" });
  }

  var users = db.get("users").value();
  const user = users.find((u) => u["username"] === username);
  if (!!user && user["username"] === username) {
    if (!bcrypt.compareSync(password, user["password"])) {
      return res.json({ error: "wrong password" });
    } else {
      const token = jwt.sign(
        {
          username: user["username"],
          email: user["email"],
        },
        JWT_SECRET,
        { expiresIn: "1d" }
      );

      const onlineUsers = db.get("online").value();
      var onlineUser = onlineUsers.find(
        (o) => o["username"] === user["username"]
      );
      if (!!onlineUser) {
        onlineUser["token"] = token;
      } else {
        onlineUser = user;
        onlineUsers.push(onlineUser);
      }

      db.write();

      return res.json({
        user: {
          username: user["username"],
          email: user["email"],
        },
        token,
      });
    }
  }
  return res.json({ error: "user not found" });
});

app.post("/api/auth/signup", async (req, res) => {
  const { username, email, password } = req.body;
  if (!!!username) {
    return res.json({ error: "username is required" });
  }
  if (!!!email) {
    return res.json({ error: "email is required" });
  }
  if (!!!password || password.length < 6) {
    return res.json({ error: "password must be at least 6 characters long" });
  }

  const users = db.get("users").value();
  const userfound = users.find(
    (u) => u["username"] === username || u["email"] === username
  );
  if (!!userfound && userfound["username"] === username) {
    return res.json({ error: "username is taken" });
  }
  if (!!userfound && userfound["email"] === email) {
    return res.json({ error: "email is taken" });
  }
  const encryptedPassword = bcrypt.hashSync(password, salt);
  const user = {
    username,
    email,
    password: encryptedPassword,
  };
  users.push(user);

  db.write();

  const token = jwt.sign(
    {
      username: user["username"],
      email: user["email"],
    },
    JWT_SECRET,
    { expiresIn: "1d" }
  );

  const onlineUsers = db.get("online").value();
  var onlineUser = onlineUsers.find((o) => o["username"] === user["username"]);
  if (!!onlineUser) {
    onlineUser["token"] = token;
  } else {
    onlineUser = user;
    onlineUsers.push(onlineUser);
  }
  db.write();

  return res.json({
    user: {
      username: user["username"],
      email: user["email"],
    },
    token,
  });
});

app.get("/api/auth/signout", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.json({ error: "no token provided" });
  }
  const userverity = jwt.verify(token, JWT_SECRET);
  if (!!userverity) {
    const users = db.get("users").value();
    const userfound = users.find(
      (u) =>
        u["username"] == userverity["username"] &&
        u["email"] == userverity["email"]
    );
    if (!!userfound) {
      const onlineUsers = db.get("online").value();
      const onlineUser = onlineUsers.find(
        (o) => o["username"] === userfound["username"]
      );
      if (!!onlineUser) {
        onlineUsers.splice(onlineUsers.indexOf(onlineUser), 1);
      }
      db.write();
      return res.json({
        status: true,
      });
    }
  }
  return res.json({ error: "user not found" });
});

app.get("/api/v1/profile", (req, res) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.json({ error: "no token provided" });
  }
  const userverity = jwt.verify(token, JWT_SECRET);
  if (!!userverity) {
    const users = db.get("users").value();
    const userfound = users.find(
      (u) =>
        u["username"] == userverity["username"] &&
        u["email"] == userverity["email"]
    );
    if (!!userfound) {
      const onlineUsers = db.get("online").value();
      const onlineUser = onlineUsers.find(
        (o) => o["username"] === userfound["username"]
      );
      if (!!onlineUser) {
        return res.json({
          user: {
            username: userfound["username"],
            email: userfound["email"],
          },
        });
      }
    }
  }
  return res.json({ error: "user not found" });
});

// Send user data - used by client.js
app.get("/users", async (req, res) => {
  var users = db.get("users").value(); // finds all entries in the users table
  res.send(users); // sends users back to the page
});

// Create a new entry in the users table
app.post("/new", async (req, res) => {
  db.get("users")
    .push({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, salt),
    })
    .write();
  res.redirect("/");
});

// Empties the database and re-populates users with the default users
app.get("/reset", async (req, res) => {
  // Clear the databaase
  db.get("users").remove().write();

  res.redirect("/");
});

app.get("/", async (req, res) => {
  res.sendFile(path.join(srcPath, "public", "index.html"));
});

// Listen on port 8080
var listener = app.listen(8080, function () {
  console.log("Listening on port " + listener.address().port);
});
