import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";

import { PORT } from "./config/env.js";

import oliveRouter from "./routes/olive.routes.js";
import authRouter from "./routes/auth.routes.js";
import userRouter from "./routes/user.routes.js";
import connectToDatabase from "./database/mongodb.js";
import errorMiddleware from "./middlewares/error.middleware.js";
import arcjetMiddleware from "./middlewares/arcjet.middleware.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(arcjetMiddleware);

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/users", userRouter);
app.use("/api/v1/olives", oliveRouter);

app.use(errorMiddleware);

app.get("/", (req, res) => {
  res.send("Welcome to api");
});

app.listen(PORT, async () => {
  console.log(`api running on http://localhost:${PORT}`);

  await connectToDatabase();
});

export default app;
