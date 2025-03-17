import { Router } from 'express';

import { signUp, signIn, signOut, refresh } from '../controllers/auth.controller.js';

const authRouter = Router();

// path: /api/v1/auth
authRouter.post('/sign-up', signUp);
authRouter.post('/sign-in', signIn);
authRouter.post('/sign-out', signOut);
authRouter.get("/refresh", refresh);

export default authRouter;