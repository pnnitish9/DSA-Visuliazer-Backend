import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "./models/User.js";
import {
  validateRegister,
  validateLogin,
} from "./validators/authValidator.js";

dotenv.config();

const app = express();

// -------------------- Middleware --------------------

app.use(express.json());

const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://easydsa.vercel.app",
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn("Blocked CORS:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

// -------------------- MongoDB Connection --------------------

let isConnected = false;

async function connectToDB() {
  if (isConnected) return;

  try {
    await mongoose.connect(process.env.MONGO_URI);

    isConnected = true;

    console.log("MongoDB Connected");
  } catch (err) {
    console.error("MongoDB Connection Error:", err);
    throw err;
  }
}

app.use(async (req, res, next) => {
  try {
    await connectToDB();
    next();
  } catch (err) {
    return res.status(500).json({
      message: "Database connection failed",
    });
  }
});

// -------------------- Health Check --------------------

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Backend is running",
  });
});

// -------------------- JWT Middleware --------------------

const verifyToken = (req, res, next) => {
  try {
    const auth = req.headers.authorization;

    if (!auth) {
      return res.status(401).json({
        message: "No token provided",
      });
    }

    const token = auth.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({
      message: "Invalid token",
    });
  }
};

// -------------------- Register --------------------

app.post("/api/register", async (req, res) => {
  try {
    validateRegister(req.body);

    const { name, gender, dob, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      gender,
      dob,
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User registered successfully",
      userId: user._id,
    });
  } catch (err) {
    console.error("Register Error:", err);

    res.status(400).json({
      message: err.message,
    });
  }
});

// -------------------- Login --------------------

app.post("/api/login", async (req, res) => {
  try {
    validateLogin(req.body);

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        name: user.name,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "2d",
      }
    );

    res.json({ token });
  } catch (err) {
    console.error("Login Error:", err);

    res.status(400).json({
      message: err.message,
    });
  }
});

// -------------------- Current User --------------------

app.get("/api/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json({ user });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Server error",
    });
  }
});

// -------------------- User Account --------------------

app.get("/api/useraccount", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json({ user });
  } catch (err) {
    res.status(500).json({
      message: "Server error",
    });
  }
});

// -------------------- Update Account --------------------

app.put("/api/useraccount", verifyToken, async (req, res) => {
  try {
    const { name, gender, dob, email, password } = req.body;

    const updates = {
      name,
      gender,
      dob,
      email,
    };

    if (password && password.trim() !== "") {
      updates.password = await bcrypt.hash(password, 10);
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      updates,
      {
        new: true,
        runValidators: true,
      }
    ).select("-password");

    if (!updatedUser) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json({
      message: "Account updated successfully",
      user: updatedUser,
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Server error",
    });
  }
});

// -------------------- Delete Account --------------------

app.delete("/api/useraccount", verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.id);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json({
      message: "Account deleted successfully",
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      message: "Server error",
    });
  }
});

export default app;