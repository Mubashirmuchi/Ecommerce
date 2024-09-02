import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { redis } from "../lib/redis.js";

dotenv.config();

const generateTokens = (userId) => {
  const acessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { acessToken, refreshToken };
};

const storeRefreshToken = async (userId, refreshToken) => {
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60
  ); // 7 days
};

const setCookie = (res, acessToken, refreshToken) => {
  res.cookie("accessToken", acessToken, {
    httpOnly: true, // prevent xss attacks,cross site scripting attacks
    secure: process.NODE_ENV === "production",
    sameSite: "strict", // prevent csrv attack , cross site request forgery attack
    maxAge: 15 * 60 * 1000,
  });
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true, // prevent xss attacks,cross site scripting attacks
    secure: process.NODE_ENV === "production",
    sameSite: "strict", // prevent csrv attack , cross site request forgery attack
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

export const signup = async (req, res) => {
  const { email, password, name } = req.body;
  try {
    const userExist = await User.findOne({ email });

    if (userExist) {
      return res.status(400).json({ message: "User already exists" });
    }
    const user = await User.create({ name, email, password });

    // authenticate
    const { acessToken, refreshToken } = generateTokens(user._id);

    await storeRefreshToken(user._id, refreshToken);

    setCookie(res, acessToken, refreshToken);

    res.status(201).json({ user:{
        _id:user._id,
        name:user.email,
        role:user.role,
    }, message: "User Created succesfully " });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
export const login = (req, res) => {
  res.send("login caller");
};
export const logout = (req, res) => {
  res.send("logout caller");
};
