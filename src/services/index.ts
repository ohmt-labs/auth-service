import config from '../config/env';
import RedisService from './RedisService';
import JwtAuthService from './JwtAuthService';

export const redisService = new RedisService(config);
export const jwtAuthService = new JwtAuthService(config, redisService);

jwtAuthService.configurePassport();

export default {
	redisService,
	jwtAuthService,
};