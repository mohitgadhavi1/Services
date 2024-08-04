const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const { authenticator } = require("otplib");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

// Load User model
const User = require("../models/User");

// Set up Nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Rate limiter for OTP verification and password reset requests
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: "Too many OTP verification attempts, please try again later",
});

// Register user
router.post("/register", (req, res) => {
  const { name, email, password } = req.body;
  let errors = [];

  if (!name || !email || !password) {
    errors.push({ msg: "Please enter all fields" });
  }

  if (password.length < 6) {
    errors.push({ msg: "Password must be at least 6 characters" });
  }

  if (errors.length > 0) {
    return res.status(400).json(errors);
  }

  User.findOne({ email: email }).then((user) => {
    if (user) {
      return res.status(400).json([{ msg: "Email already exists" }]);
    } else {
      const newUser = new User({
        name,
        email,
        password,
      });

      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;

          // Generate OTP
          const otp = authenticator.generate(process.env.OTP_SECRET);
          newUser.otp = otp;
          newUser.otpExpires = Date.now() + 3600000; // 1 hour

          newUser
            .save()
            .then((user) => {
              // Send OTP email
              const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: "Email Verification OTP",
                text: `Your OTP for email verification is: ${otp}`,
              };

              transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                  return console.log(error);
                }
                res.json({
                  msg: "Registration successful, please verify your email.",
                });
              });
            })
            .catch((err) => console.log(err));
        });
      });
    }
  });
});

// Verify OTP
router.post("/verify-otp", otpLimiter, (req, res) => {
  const { email, otp } = req.body;

  User.findOne({ email: email }).then((user) => {
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    if (
      authenticator.check(otp, process.env.OTP_SECRET) &&
      user.otpExpires > Date.now()
    ) {
      user.isVerified = true;
      user.otp = undefined;
      user.otpExpires = undefined;

      user
        .save()
        .then((user) => {
          res.json({ msg: "Email verified successfully" });
        })
        .catch((err) => console.log(err));
    } else {
      res.status(400).json({ msg: "Invalid or expired OTP" });
    }
  });
});

// Login user
router.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user)
      return res.status(400).json({ msg: "Invalid email or password" });
    if (!user.isVerified)
      return res.status(400).json({ msg: "Email not verified" });

    req.logIn(user, (err) => {
      if (err) return next(err);

      const payload = { id: user.id, name: user.name, email: user.email };
      jwt.sign(
        payload,
        process.env.JWT_SECRET,
        { expiresIn: 3600 },
        (err, token) => {
          if (err) throw err;
          res.json({ token: "Bearer " + token });
        }
      );
    });
  })(req, res, next);
});

// Request password reset
router.post("/reset-password", otpLimiter, (req, res) => {
  const { email } = req.body;

  User.findOne({ email }).then((user) => {
    if (!user) {
      return res.status(400).json({ msg: "User not found" });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString("hex");
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    user.save().then((user) => {
      // Send reset email
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: user.email,
        subject: "Password Reset",
        text: `You are receiving this email because you (or someone else) have requested to reset the password for your account.\n\n
               Please click on the following link, or paste it into your browser to complete the process within one hour of receiving it:\n\n
               http://localhost:5000/reset/${resetToken}\n\n
               If you did not request this, please ignore this email and your password will remain unchanged.\n`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return console.log(error);
        }
        res.json({ msg: "Password reset email sent." });
      });
    });
  });
});

// Reset password
router.post("/reset/:token", (req, res) => {
  const { password } = req.body;

  User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  }).then((user) => {
    if (!user) {
      return res
        .status(400)
        .json({ msg: "Password reset token is invalid or has expired" });
    }

    // Hash new password
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(password, salt, (err, hash) => {
        if (err) throw err;
        user.password = hash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save().then((user) => {
          res.json({ msg: "Password has been reset" });
        });
      });
    });
  });
});

module.exports = router;
