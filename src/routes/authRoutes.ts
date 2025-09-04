import { Router, Request, Response } from 'express';
import { jwtAuthService } from '../services';

const router = Router();

router.get('/google', jwtAuthService.startAuth());

const callbackMiddleware = jwtAuthService.handleCallback();
router.get('/google/callback', ...callbackMiddleware);

// JWT-based endpoints
router.post('/logout', jwtAuthService.logout());
router.post('/refresh', jwtAuthService.refreshToken());

router.get('/failure', (_req: Request, res: Response) => {
	res.status(401).json({ error: 'Authentication failed' });
});

export default router;