import { Router } from "express";

import authorize from '../middlewares/auth.middleware.js';
import { createOlive, getOlives } from "../controllers/olive.controller.js";

const oliveRouter = Router();

oliveRouter.get('/', authorize, getOlives);

oliveRouter.post('/', authorize, createOlive);


export default oliveRouter;
