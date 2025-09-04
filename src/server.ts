import express from 'express';
import cors from 'cors';
import passport from 'passport';
import config from './config/env';
import { jwtAuthService, redisService } from './services';
import authRouter from './routes/authRoutes';

// Extend Express Request type to include JWT user
declare global {
	namespace Express {
		interface Request {
			authUser?: {
				id: string;
				email?: string | undefined;
				name?: string | undefined;
				picture?: string | undefined;
				provider: 'google';
				loginTime: Date;
				lastActivity: Date;
				macAddress: string;
				serial: string;
			};
			tokenPayload?: any;
		}
	}
}

class AuthServiceServer {
	private app: express.Application;
	private server: any;
	private jwtAuthService = jwtAuthService;
	private redisService = redisService;

	constructor() {
		this.app = express();
		this.setupMiddleware();
		this.setupRoutes();
		this.setupGracefulShutdown();
	}

	private setupMiddleware(): void {
		this.app.use(cors({ origin: true, credentials: true }));
		this.app.use(express.json());
		
		this.app.use(passport.initialize());
		
		this.app.use((req, res, next) => {
			console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
			next();
		});
	}

	private setupRoutes(): void {
		this.app.get('/auth/me', this.jwtAuthService.requireAuth(), (req, res) => {
			const user = this.jwtAuthService.getCurrentUser(req);
			res.json({ user });
		});

		// Auth routes
		this.app.use('/auth', authRouter);
	}

	private setupGracefulShutdown(): void {
		const gracefulShutdown = async (signal: string) => {
			console.log(`Received ${signal}. Starting graceful shutdown...`);
			
			// Stop accepting new connections
			if (this.server) {
				this.server.close(async () => {
					console.log('HTTP server closed');
					
					await this.redisService.disconnect();
					
					console.log('Graceful shutdown completed');
					process.exit(0);
				});
			}

			// Force close after timeout
			setTimeout(() => {
				console.error('Forced shutdown after timeout');
				process.exit(1);
			}, 10000); // 10 second timeout
		};

		process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
		process.on('SIGINT', () => gracefulShutdown('SIGINT'));
	}

	async start(): Promise<void> {
		try {
			this.server = this.app.listen(config.port, () => {
				console.log(`🚀 Auth service listening on http://localhost:${config.port}`);
				console.log(`📊 Environment: ${config.environment}`);
				console.log(`🔐 Auth mode: JWT with Redis token storage`);
			});
		} catch (error) {
			console.error('Failed to start server:', error);
			process.exit(1);
		}
	}
}

const server = new AuthServiceServer();
server.start().catch((error) => {
	console.error('Server startup failed:', error);
	process.exit(1);
});
