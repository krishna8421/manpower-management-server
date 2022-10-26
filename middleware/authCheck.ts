import { JWT_SECRET_KEY } from "./../constants";
import jwt from "jsonwebtoken";
import { NextFunction, Request, Response } from "express";

export const authCheck = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    if (!req.headers?.authorization?.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Access denied. No token provided",
      });
    }
    const bearerHeader = req.headers.authorization;
    const token = bearerHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Access denied. Invalid token",
    });
  }
};
