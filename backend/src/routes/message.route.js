import express from "express";
import { protectRoute } from "../middleware/auth.middleware.js";
import { getMessages, getUser, sendMessage } from "../controller/message.controller.js";

const router = express.Router();

router.get("/users", protectRoute, getUser)

router.get("/:id", protectRoute, getMessages);

router.post("/send/:id", protectRoute, sendMessage);

export default router;