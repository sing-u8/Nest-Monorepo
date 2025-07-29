import { SetMetadata, UseGuards, applyDecorators } from '@nestjs/common';
import { RateLimitGuard } from '../guards/rate-limit.guard';
import { RateLimiterOptions } from '../middleware/rate-limiting.middleware';

export const RATE_LIMIT_KEY = 'rate_limit';

/**
 * Rate limit decorator for endpoint-specific rate limiting
 */
export function RateLimit(options: Partial<RateLimiterOptions>) {
  return applyDecorators(
    SetMetadata(RATE_LIMIT_KEY, options),
    UseGuards(RateLimitGuard),
  );
}

/**
 * Predefined rate limit decorators for common scenarios
 */

/**
 * Strict rate limiting for authentication endpoints
 */
export function AuthRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    message: 'Too many authentication attempts, please try again later.',
  });
}

/**
 * Very strict rate limiting for registration
 */
export function RegisterRateLimit() {
  return RateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 3,
    message: 'Too many registration attempts, please try again later.',
  });
}

/**
 * Moderate rate limiting for token refresh
 */
export function RefreshRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 50,
    message: 'Too many token refresh requests, please try again later.',
  });
}

/**
 * Rate limiting for social authentication
 */
export function SocialAuthRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 10,
    message: 'Too many social authentication attempts, please try again later.',
  });
}

/**
 * Rate limiting for profile operations
 */
export function ProfileRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    message: 'Too many profile requests, please try again later.',
  });
}

/**
 * Rate limiting for password reset operations
 */
export function PasswordResetRateLimit() {
  return RateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 5,
    message: 'Too many password reset attempts, please try again later.',
  });
}

/**
 * Rate limiting for file upload operations
 */
export function FileUploadRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 20,
    message: 'Too many file upload attempts, please try again later.',
  });
}

/**
 * Global rate limiting for general API endpoints
 */
export function GlobalRateLimit() {
  return RateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 1000,
    message: 'Too many requests, please try again later.',
  });
}