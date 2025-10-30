import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import User from "./models/User.js";
import { validateRegister,validateLogin } from "./validators/authValidator.js";

dotenv.config();

const app = express();
app.use(cors({ origin: "http://localhost:5173", credentials: true }));
app.use(bodyParser.json());

// mongoose
//   .connect(process.env.MONGO_URI, { dbName: "DSAVisualizer" })
//   .then(() => console.log("MongoDB Connected"))
//   .catch((err) => console.error("MongoDB connection error:", err));

let isConnected = false;
async function ConnectedToDB() {
      mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    })
    .then(() => {
      isConnected = true
      console.log("MongoDB Connected")
    })
    .catch(err => console.error("MongoDB Connection Error:", err));
}

// middleware 
app.use((req,res,next)=>{
  if(!isConnected){
    ConnectedToDB();
  }
  next();
})

// JWT Authentication Middleware
const verifyToken = (req, res, next) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ message: "No token provided" });

    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    // Validate input
    validateRegister(req.body);

    const { name, gender, dob, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

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
  } catch (error) {
    console.error("Register error:", error.message);
    res.status(400).json({ message: error.message || "Invalid data" });
  }
});


// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    validateLogin(req.body);

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(400).json({ message: error.message || "Invalid data" });
  }
});


// GET CURRENT USER
app.get("/api/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get user details
app.get("/api/useraccount", async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ message: "No token" });

    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password");

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ user });
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
});


// UPDATE account details
app.put("/api/useraccount", verifyToken, async (req, res) => {
  try {
    const { name, gender, dob, email, password } = req.body;

    const updates = { name, gender, dob, email };
    if (password && password.trim() !== "") {
      updates.password = await bcrypt.hash(password, 10);
    }

    const updatedUser = await User.findByIdAndUpdate(req.user.id, updates, {
      new: true,
      runValidators: true,
      select: "-password",
    });

    if (!updatedUser)
      return res.status(404).json({ message: "User not found" });

    res.json({ message: "Account updated successfully", user: updatedUser });
  } catch (error) {
    console.error("Error updating account:", error);
    res.status(500).json({ message: "Server error" });
  }
});

//DELETE account
app.delete("/api/useraccount", verifyToken, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// const PORT = process.env.PORT || 4000;
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;