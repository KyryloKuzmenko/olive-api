import { Router } from "express";

import authorize from '../middlewares/auth.middleware.js';
import { createOlive, getOlives } from "../controllers/olive.controller.js";

const oliveRouter = Router();

oliveRouter.get('/', authorize, getOlives);

oliveRouter.post('/', authorize, createOlive);

// oliveRouter.delete('/:id', (req, res) => res.send({ title: 'Delete olive' }));

export default oliveRouter;
