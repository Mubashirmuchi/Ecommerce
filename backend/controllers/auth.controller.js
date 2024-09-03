import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { redis } from "../lib/redis.js";

dotenv.config();

const generateTokens = (userId) => {
  const accessToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
};

const storeRefreshToken = async (userId, refreshToken) => {
  await redis.set(
    `refresh_token:${userId}`,
    refreshToken,
    "EX",
    7 * 24 * 60 * 60
  ); // 7 days
};

const setCookie = (res, accessToken, refreshToken) => {
  res.cookie("accessToken", accessToken, {
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
    const { accessToken, refreshToken } = generateTokens(user._id);

    await storeRefreshToken(user._id, refreshToken);

    setCookie(res, accessToken, refreshToken);

    res.status(201).json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      message: "User Created succesfully ",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await user.comparePassword(password))) {
      const { accessToken, refreshToken } = generateTokens(user._id);
      await storeRefreshToken(user._id, refreshToken);
      setCookie(res, accessToken, refreshToken);
      res.status(201).json({
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        message: "User logged in succesfully ",
      });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};



export const logout = (req, res) => {
  res.send("logout caller");
};

export const refreshToken = async (req,res)=>{
  console.log(req)
try {
  const refreshToken = req.cookie;
  console.log("rwcw",req.cookie)
if (!refreshToken) {
  return res.status(401).json({message:"No refresh token provided"})
}

const decoded = jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET)
const storeToken = await redis.get(
  `refresh_token:${decoded.userId}`);

  if (storeToken!== refreshToken ) {
    return res.status(401).json({message:"invalid refresh token"})

  }
  const accessToken = jwt.sign({userId:decoded.userId},process.env.ACCESS_TOKEN_SECRET,{
    expiresIn: "15m",
  })
  res.cookie("accessToken", accessToken, {
    httpOnly: true, 
    secure: process.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 15 * 60 * 1000,
  });
  
  return res.status(200).json({message:"Token refreshed succesfully"})

} catch (error) {
  res.status(500).json({ message: error.message });

}
}