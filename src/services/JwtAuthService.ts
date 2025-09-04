import passport from 'passport';
import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import type { AppConfig } from '../config/env';
import RedisService from './RedisService';

export interface JwtTokenPayload {
	sub: string;
	email?: string;
	name?: string;
	picture?: string;
	provider: 'google';
	macAddress: string;
	serial: string;
	iat: number;
	exp: number;
}

export interface AuthUser {
	id: string;
	email?: string | undefined;
	name?: string | undefined;
	picture?: string | undefined;
	provider: 'google';
	loginTime: Date;
	lastActivity: Date;
	macAddress: string;
	serial: string;
}

export class JwtAuthService {
	private readonly _config: AppConfig;
	private readonly _redisService: RedisService;

	constructor(config: AppConfig, redisService: RedisService) {
		this._config = config;
		this._redisService = redisService;
	}

	configurePassport(): void {
		passport.use(
			new GoogleStrategy(
				{
					clientID: this._config.googleClientId,
					clientSecret: this._config.googleClientSecret,
					callbackURL: this._config.oauthCallbackUrl,
				},
				(_accessToken, _refreshToken, profile, done) => {
					done(null, profile);
				}
			)
		);
	}

	startAuth() {
		return passport.authenticate('google', {
			scope: ['profile', 'email'],
			session: false,
			prompt: 'select_account',
		});
	}

	handleCallback() {
		return [
			passport.authenticate('google', {
				session: false,
				failureRedirect: '/auth/failure',
			}),
			async (req: Request, res: Response) => {
				try {
					const profile = req.user as Profile;
					const macAddress = this._extractMacAddress(req);
					const serial = this._generateSerial();
					
					// Create user data
					const authUser: AuthUser = {
						id: profile.id,
						email: profile.emails && profile.emails[0] ? profile.emails[0].value : undefined,
						name: profile.displayName,
						picture: profile.photos && profile.photos[0] ? profile.photos[0].value : undefined,
						provider: 'google',
						loginTime: new Date(),
						lastActivity: new Date(),
						macAddress,
						serial,
					};

					// Create JWT payload
					const payload: JwtTokenPayload = {
						sub: profile.id,
						name: profile.displayName,
						provider: 'google',
						macAddress,
						serial,
						iat: Math.floor(Date.now() / 1000),
						exp: Math.floor(Date.now() / 1000) + this._config.jwtExpirationTime,
					};

					if (authUser.email) {
						payload.email = authUser.email;
					}
					if (authUser.picture) {
						payload.picture = authUser.picture;
					}

					const token = jwt.sign(payload, this._config.jwtSecret);

					// Store token in Redis with MAC address and serial as key
					const redisKey = `jwt:${macAddress}:${serial}`;
					await this._redisService.setWithExpiry(redisKey, JSON.stringify(authUser), this._config.jwtExpirationTime);

					// Also store a reverse lookup for the user ID to prevent duplicate sessions
					const userSessionsKey = `user_sessions:${profile.id}`;
					await this._redisService.addToSet(userSessionsKey, redisKey);
					await this._redisService.expire(userSessionsKey, this._config.jwtExpirationTime);

					if (this._config.clientAppUrl) {
						const url = new URL(this._config.clientAppUrl);
						url.searchParams.set('token', token);
						res.redirect(url.toString());
						return;
					}

					res.json({ 
						token, 
						user: payload,
						macAddress,
						serial
					});
				} catch (error) {
					console.error('Authentication callback error:', error);
					res.status(500).json({ error: 'Authentication failed' });
				}
			},
		] as [
			(req: Request, res: Response, next: NextFunction) => void,
			(req: Request, res: Response) => void
		];
	}

	// Middleware to verify JWT token and check Redis
	requireAuth() {
		return async (req: Request, res: Response, next: NextFunction) => {
			try {
				const token = this._extractTokenFromRequest(req);
				if (!token) {
					return res.status(401).json({ error: 'No token provided' });
				}

				const decoded = jwt.verify(token, this._config.jwtSecret) as JwtTokenPayload;
				
				const redisKey = `jwt:${decoded.macAddress}:${decoded.serial}`;
				const userData = await this._redisService.get(redisKey);
				
				if (!userData) {
					return res.status(401).json({ error: 'Token expired or invalid' });
				}

				const user: AuthUser = JSON.parse(userData);
				user.lastActivity = new Date();
				await this._redisService.setWithExpiry(redisKey, JSON.stringify(user), this._config.jwtExpirationTime);

				(req as any).authUser = user;
				(req as any).tokenPayload = decoded;

				next();
			} catch (error) {
				if (error instanceof jwt.JsonWebTokenError) {
					return res.status(401).json({ error: 'Invalid token' });
				}
				console.error('Auth middleware error:', error);
				res.status(500).json({ error: 'Authentication failed' });
			}
		};
	}

	getCurrentUser(req: Request): AuthUser | null {
		return (req as any).authUser || null;
	}

	logout() {
		return async (req: Request, res: Response) => {
			try {
				const token = this._extractTokenFromRequest(req);
				if (!token) {
					return res.status(400).json({ error: 'No token provided' });
				}

				const decoded = jwt.verify(token, this._config.jwtSecret) as JwtTokenPayload;
				const redisKey = `jwt:${decoded.macAddress}:${decoded.serial}`;
				
				await this._redisService.del(redisKey);
				
				const userSessionsKey = `user_sessions:${decoded.sub}`;
				await this._redisService.removeFromSet(userSessionsKey, redisKey);

				res.json({ 
					message: 'Logged out successfully',
					mode: 'jwt',
					timestamp: new Date().toISOString()
				});
			} catch (error) {
				console.error('Logout error:', error);
				res.status(500).json({ error: 'Logout failed' });
			}
		};
	}

	refreshToken() {
		return async (req: Request, res: Response) => {
			try {
				const token = this._extractTokenFromRequest(req);
				if (!token) {
					return res.status(400).json({ error: 'No token provided' });
				}

				const decoded = jwt.verify(token, this._config.jwtSecret) as JwtTokenPayload;
				const redisKey = `jwt:${decoded.macAddress}:${decoded.serial}`;
				
				// Check if token exists in Redis
				const userData = await this._redisService.get(redisKey);
				if (!userData) {
					return res.status(401).json({ error: 'Token expired or invalid' });
				}

				const user: AuthUser = JSON.parse(userData);
				user.lastActivity = new Date();

				// Extend expiration in Redis
				await this._redisService.setWithExpiry(redisKey, JSON.stringify(user), this._config.jwtExpirationTime);

				// Create new JWT token with updated expiration
				const newPayload: JwtTokenPayload = {
					...decoded,
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + this._config.jwtExpirationTime,
				};

				const newToken = jwt.sign(newPayload, this._config.jwtSecret);

				res.json({ 
					token: newToken, 
					user: newPayload,
					message: 'Token refreshed successfully'
				});
			} catch (error) {
				console.error('Token refresh error:', error);
				res.status(500).json({ error: 'Token refresh failed' });
			}
		};
	}



	// Extract MAC address from request
	private _extractMacAddress(req: Request): string {
		const forwardedFor = req.headers['x-forwarded-for'];
		const realIp = req.headers['x-real-ip'];
		const clientIp = req.connection.remoteAddress || req.socket.remoteAddress;
		
		const ip = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor || realIp || clientIp || 'unknown';
		
		const userAgent = req.headers['user-agent'] || 'unknown';
		return crypto.createHash('sha256').update(`${ip}-${userAgent}`).digest('hex').substring(0, 16);
	}

	private _generateSerial(): string {
		return crypto.randomBytes(8).toString('hex');
	}

	private _extractTokenFromRequest(req: Request): string | null {
		const authHeader = req.headers.authorization;
		if (authHeader && authHeader.startsWith('Bearer ')) {
			return authHeader.substring(7);
		}
		
		// Also check query parameter for OAuth callback
		if (req.query.token && typeof req.query.token === 'string') {
			return req.query.token;
		}
		
		return null;
	}
}

export default JwtAuthService;
