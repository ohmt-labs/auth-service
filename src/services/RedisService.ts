import { createClient, RedisClientType } from 'redis';
import type { AppConfig } from '../config/env';

export default class RedisService {
	private _client: RedisClientType | null = null;
	private readonly _config: AppConfig;

	constructor(config: AppConfig) {
		this._config = config;
		// Attempt initial connection; exit the process on failure
		void this.connect().catch((error) => {
			console.error('Fatal: Redis initial connection failed:', error);
			process.exit(1);
		});
	}

	async connect(): Promise<void> {
		if (!this._config.redisUrl) {
			throw new Error('Redis URL not configured');
		}

		try {
			this._client = createClient({ url: this._config.redisUrl });
			await this._client.connect();
			console.log('Connected to Redis for JWT token storage');
		} catch (error) {
			console.error('Redis connection failed:', error);
			throw error;
		}
	}

	async disconnect(): Promise<void> {
		if (this._client) {
			await this._client.quit();
			this._client = null;
			console.log('Disconnected from Redis');
		}
	}

	async isConnected(): Promise<boolean> {
		if (!this._client) {
			return false;
		}
		try {
			await this._client.ping();
			return true;
		} catch {
			return false;
		}
	}

	async setWithExpiry(key: string, value: string, ttlSeconds: number): Promise<void> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		await this._client.setEx(key, ttlSeconds, value);
	}

	async get(key: string): Promise<string | null> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.get(key);
	}

	async del(key: string): Promise<number> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.del(key);
	}

	async expire(key: string, ttlSeconds: number): Promise<void> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		await this._client.expire(key, ttlSeconds);
	}

	async addToSet(key: string, member: string): Promise<number> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.sAdd(key, member);
	}

	async removeFromSet(key: string, member: string): Promise<number> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.sRem(key, member);
	}

	async getSetMembers(key: string): Promise<string[]> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.sMembers(key);
	}

	async exists(key: string): Promise<boolean> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		const result = await this._client.exists(key);
		return result === 1;
	}

	async ttl(key: string): Promise<number> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.ttl(key);
	}

	async getInfo(): Promise<string> {
		if (!this._client) {
			throw new Error('Redis client not connected');
		}
		return await this._client.info();
	}

	async healthCheck(): Promise<{ status: string; connected: boolean; error?: string }> {
		try {
			const connected = await this.isConnected();
			if (connected) {
				await this._client!.ping();
				return { status: 'healthy', connected: true };
			} else {
				return { status: 'unhealthy', connected: false, error: 'Not connected' };
			}
		} catch (error) {
			return { 
				status: 'unhealthy', 
				connected: false, 
				error: error instanceof Error ? error.message : 'Unknown error' 
			};
		}
	}
}
