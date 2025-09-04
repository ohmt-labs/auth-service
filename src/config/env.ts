import dotenv from 'dotenv';

dotenv.config();

function getRequired(name: string): string {
	const value = process.env[name];
	if (!value) {
		throw new Error(`Missing required env var: ${name}`);
	}
	return value;
}

export interface AppConfig {
	// Service Configuration
	port: number;
	environment: string;
	
	// OAuth Configuration
	googleClientId: string;
	googleClientSecret: string;
	oauthCallbackUrl: string;
	jwtSecret: string;
	jwtExpirationTime: number;
	clientAppUrl?: string;
	
	// Redis Configuration
	redisUrl: string;
}

const baseConfig: AppConfig = {
	port: Number(process.env.PORT) || 3000,
	environment: process.env.NODE_ENV || 'development',
	
	googleClientId: getRequired('GOOGLE_CLIENT_ID'),
	googleClientSecret: getRequired('GOOGLE_CLIENT_SECRET'),
	oauthCallbackUrl: getRequired('OAUTH_CALLBACK_URL'),
	jwtSecret: getRequired('JWT_SECRET'),
	jwtExpirationTime: Number(process.env.JWT_EXPIRATION_TIME) || 60 * 60, // 1 hour in seconds

    redisUrl: getRequired('REDIS_URL'),
};

// Add optional properties only if they exist
if (process.env.CLIENT_APP_URL) {
	baseConfig.clientAppUrl = process.env.CLIENT_APP_URL;
}

export const config = baseConfig;

export default config;


