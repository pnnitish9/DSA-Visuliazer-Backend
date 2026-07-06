// validators/authValidator.js
import validator from "validator";

// ✅ REGISTER VALIDATOR
export function validateRegister(data) {
  // name
  if (!data.name || validator.isEmpty(data.name.trim())) {
    throw new Error("Name is required");
  }
  if (!validator.isLength(data.name, { min: 3 })) {
    throw new Error("Name must be at least 3 characters long");
  }

  // email
  if (!data.email || validator.isEmpty(data.email)) {
    throw new Error("Email is required");
  }
  if (!validator.isEmail(data.email)) {
    throw new Error("Invalid email format");
  }

  // password
  if (!data.password || validator.isEmpty(data.password)) {
    throw new Error("Password is required");
  }
  if (!validator.isStrongPassword(data.password)) {
    throw new Error(
      "Password must be strong (min 8 chars, include uppercase, lowercase, number & symbol)"
    );
  }
}

// ✅ LOGIN VALIDATOR
export function validateLogin(data) {
  if (!data.email || validator.isEmpty(data.email)) {
    throw new Error("Email is required");
  }
  if (!validator.isEmail(data.email)) {
    throw new Error("Invalid email format");
  }

  if (!data.password || validator.isEmpty(data.password)) {
    throw new Error("Password is required");
  }
}
