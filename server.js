const express = require("express");
const db = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}

app.get("/", (req, res) => {
  res.send("Authentication Server Running");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

// Signup route
//const bcrypt = require("bcrypt");
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], async (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length > 0) {
      return res.status(400).send("Email already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const verificationCode = generateOTP();

    const verificationExpires = new Date(Date.now() + 10 * 60 * 1000);

    const insertSql = `
            INSERT INTO users
            (name, email, password, verification_code, verification_expires)
            VALUES (?, ?, ?, ?, ?)
        `;

    db.query(
      insertSql,
      [name, email, hashedPassword, verificationCode, verificationExpires],
      (err, result) => {
        if (err) {
          return res.status(500).send("Signup failed");
        }

        console.log("Verification code:", verificationCode);

        res.status(201).json({
          message: "Signup successful. Verify your account.",
          verificationCode: verificationCode,
        });
      },
    );
  });
});

// app.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;

//   const sql = "SELECT * FROM users WHERE email = ?";

//   db.query(sql, [email], async (err, result) => {
//     if (err) {
//       return res.status(500).send("Database error");
//     }

//     if (result.length > 0) {
//       return res.status(400).send("Email already exists");
//     }

//     const hashedPassword = await bcrypt.hash(password, 10);

//     const insertSql =
//       "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";

//     db.query(insertSql, [name, email, hashedPassword], (err, result) => {
//       if (err) {
//         return res.status(500).send("Signup failed");
//       }

//       res.status(201).send("Signup successful");
//     });
//   });
// });

// const bcrypt = require("bcrypt");

// app.post("/signup", async (req, res) => {
//   const { name, email, password } = req.body;

//   console.log(name);
//   console.log(email);
//   console.log(password);

//   res.send("Signup request received");
// });
// signin route
app.post("/signin", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], async (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length === 0) {
      return res.status(401).send("Invalid email or password");
    }

    const user = result[0];

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).send("Invalid email or password");
    }
    if (!user.is_verified) {
      return res.status(403).send("Please verify your account first");
    }

    const token = jwt.sign({ id: user.id, email: user.email }, "mysecretkey", {
      expiresIn: "1h",
    });

    res.status(200).json({
      message: "Signin successful",
      token: token,
    });

    // res.status(200).send("Signin successful");
  });
});

//authentication middleware
//const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).send("Access token required");
  }

  jwt.verify(token, "mysecretkey", (err, user) => {
    if (err) {
      return res.status(403).send("Invalid or expired token");
    }

    req.user = user;

    next();
  });
}

// Protected route
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Welcome to your profile",
    user: req.user,
  });
});

// Verify account route

app.post("/verify-account", (req, res) => {
  const { email, verificationCode } = req.body;

  const sql = `
        SELECT * FROM users
        WHERE email = ?
    `;

  db.query(sql, [email], (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = result[0];

    // Check OTP
    if (user.verification_code != verificationCode) {
      return res.status(400).send("Invalid verification code");
    }

    // Check OTP expiry
    if (new Date() > new Date(user.verification_expires)) {
      return res.status(400).send("Verification code expired");
    }

    // Verify account
    const updateSql = `
            UPDATE users
            SET is_verified = 1,
                verification_code = NULL,
                verification_expires = NULL
            WHERE email = ?
        `;

    db.query(updateSql, [email], (err, result) => {
      if (err) {
        return res.status(500).send("Verification failed");
      }

      res.status(200).send("Account verified successfully");
    });
  });
});

// post/forgot-password route
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length === 0) {
      return res.status(404).send("User not found");
    }

    const resetCode = generateOTP();

    const resetExpires = new Date(Date.now() + 10 * 60 * 1000);

    const updateSql = `
            UPDATE users
            SET reset_code = ?,
                reset_expires = ?
            WHERE email = ?
        `;

    db.query(updateSql, [resetCode, resetExpires, email], (err, result) => {
      if (err) {
        return res.status(500).send("Failed to create reset code");
      }

      console.log("Reset OTP:", resetCode);

      res.status(200).json({
        message: "Reset OTP generated",
        resetCode: resetCode,
      });
    });
  });
});

// verify reset otp route
app.post("/verify-reset-otp", (req, res) => {
  const { email, resetCode } = req.body;

  const sql = `
        SELECT * FROM users
        WHERE email = ?
    `;

  db.query(sql, [email], (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = result[0];

    // Check OTP
    if (user.reset_code != resetCode) {
      return res.status(400).send("Invalid reset code");
    }

    // Check expiry
    if (new Date() > new Date(user.reset_expires)) {
      return res.status(400).send("Reset code expired");
    }

    // Mark reset OTP as verified
    const updateSql = `
            UPDATE users
            SET reset_verified = 1
            WHERE email = ?
        `;

    db.query(updateSql, [email], (err, result) => {
      if (err) {
        return res.status(500).send("Failed to verify reset code");
      }

      res.status(200).send("Reset code verified successfully");
    });
  });
});

// reset password route
app.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  const sql = `
        SELECT * FROM users
        WHERE email = ?
    `;

  db.query(sql, [email], async (err, result) => {
    if (err) {
      return res.status(500).send("Database error");
    }

    if (result.length === 0) {
      return res.status(404).send("User not found");
    }

    const user = result[0];

    // Check if OTP was verified
    if (!user.reset_verified) {
      return res.status(400).send("Please verify reset OTP first");
    }

    // Check if reset code has expired
    if (new Date() > new Date(user.reset_expires)) {
      return res.status(400).send("Reset code expired");
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    const updateSql = `
            UPDATE users
            SET password = ?,
                reset_code = NULL,
                reset_expires = NULL,
                reset_verified = 0
            WHERE email = ?
        `;

    db.query(updateSql, [hashedPassword, email], (err, result) => {
      if (err) {
        return res.status(500).send("Password reset failed");
      }

      res.status(200).send("Password reset successful");
    });
  });
});
