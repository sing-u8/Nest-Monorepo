import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { HealthIndicator, HealthIndicatorResult, HealthCheckError } from '@nestjs/terminus';
import { firstValueFrom, timeout, catchError } from 'rxjs';
import { of } from 'rxjs';

/**
 * External Services Health Indicator
 * 
 * Monitors the health of external dependencies including OAuth providers,
 * third-party APIs, and other external services that the auth service depends on.
 */
@Injectable()
export class ExternalServicesHealthIndicator extends HealthIndicator {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    super();
  }

  /**
   * Check Google OAuth service health
   * 
   * @param key - Health check identifier
   * @param timeoutMs - Request timeout in milliseconds
   * @returns Health check result for Google OAuth service
   */
  async checkGoogleOAuth(key: string, timeoutMs = 5000): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Test Google's OAuth discovery endpoint
      const discoveryUrl = 'https://accounts.google.com/.well-known/openid_configuration';
      
      const response = await firstValueFrom(
        this.httpService.get(discoveryUrl).pipe(
          timeout(timeoutMs),
          catchError(error => of({ data: null, status: 0, error: error.message }))
        )
      );

      const responseTime = Date.now() - startTime;

      if (!response.data || response.status !== 200) {
        throw new Error(`Google OAuth service unreachable: ${response.error || 'Unknown error'}`);
      }

      const result = this.getStatus(key, true, {
        status: 'up',
        service: 'Google OAuth',
        endpoint: discoveryUrl,
        responseTime: `${responseTime}ms`,
        discovery: {
          issuer: response.data.issuer,
          authEndpoint: response.data.authorization_endpoint,
          tokenEndpoint: response.data.token_endpoint,
          userInfoEndpoint: response.data.userinfo_endpoint,
        },
        timestamp: new Date().toISOString(),
      });

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        service: 'Google OAuth',
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('Google OAuth service health check failed', result);
    }
  }

  /**
   * Check Apple OAuth service health
   * 
   * @param key - Health check identifier
   * @param timeoutMs - Request timeout in milliseconds
   * @returns Health check result for Apple OAuth service
   */
  async checkAppleOAuth(key: string, timeoutMs = 5000): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      // Test Apple's public keys endpoint
      const keysUrl = 'https://appleid.apple.com/auth/keys';
      
      const response = await firstValueFrom(
        this.httpService.get(keysUrl).pipe(
          timeout(timeoutMs),
          catchError(error => of({ data: null, status: 0, error: error.message }))
        )
      );

      const responseTime = Date.now() - startTime;

      if (!response.data || response.status !== 200 || !response.data.keys) {
        throw new Error(`Apple OAuth service unreachable: ${response.error || 'Invalid response'}`);
      }

      const result = this.getStatus(key, true, {
        status: 'up',
        service: 'Apple OAuth',
        endpoint: keysUrl,
        responseTime: `${responseTime}ms`,
        keys: {
          count: response.data.keys.length,
          algorithms: [...new Set(response.data.keys.map((key: any) => key.alg))],
        },
        timestamp: new Date().toISOString(),
      });

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        service: 'Apple OAuth',
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('Apple OAuth service health check failed', result);
    }
  }

  /**
   * Check all external OAuth services
   * 
   * @param key - Health check identifier
   * @param timeoutMs - Request timeout in milliseconds
   * @returns Aggregate health check result for all OAuth services
   */
  async checkAllOAuthServices(key: string, timeoutMs = 5000): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      const [googleResult, appleResult] = await Promise.allSettled([
        this.checkGoogleOAuth('google', timeoutMs),
        this.checkAppleOAuth('apple', timeoutMs),
      ]);

      const responseTime = Date.now() - startTime;
      
      const googleStatus = googleResult.status === 'fulfilled' ? 'up' : 'down';
      const appleStatus = appleResult.status === 'fulfilled' ? 'up' : 'down';
      
      const overallStatus = googleStatus === 'up' && appleStatus === 'up';
      
      const details = {
        status: overallStatus ? 'up' : 'degraded',
        responseTime: `${responseTime}ms`,
        services: {
          google: {
            status: googleStatus,
            error: googleResult.status === 'rejected' ? googleResult.reason.message : null,
          },
          apple: {
            status: appleStatus,
            error: appleResult.status === 'rejected' ? appleResult.reason.message : null,
          },
        },
        summary: {
          total: 2,
          healthy: (googleStatus === 'up' ? 1 : 0) + (appleStatus === 'up' ? 1 : 0),
        },
        timestamp: new Date().toISOString(),
      };

      const result = this.getStatus(key, overallStatus, details);

      if (!overallStatus) {
        throw new HealthCheckError('Some OAuth services are unhealthy', result);
      }

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('OAuth services health check failed', result);
    }
  }

  /**
   * Check DNS resolution health
   * 
   * @param key - Health check identifier
   * @param domain - Domain to test DNS resolution
   * @returns Health check result for DNS resolution
   */
  async checkDNSResolution(key: string, domain = 'google.com'): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      const dns = await import('dns');
      const util = await import('util');
      const lookup = util.promisify(dns.lookup);
      
      const result = await lookup(domain);
      const responseTime = Date.now() - startTime;

      const healthResult = this.getStatus(key, true, {
        status: 'up',
        service: 'DNS Resolution',
        domain,
        resolvedAddress: result.address,
        family: result.family === 4 ? 'IPv4' : 'IPv6',
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      return healthResult;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        service: 'DNS Resolution',
        domain,
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('DNS resolution health check failed', result);
    }
  }

  /**
   * Check network connectivity to external endpoints
   * 
   * @param key - Health check identifier
   * @param endpoints - List of endpoints to test
   * @param timeoutMs - Request timeout in milliseconds
   * @returns Health check result for network connectivity
   */
  async checkNetworkConnectivity(
    key: string, 
    endpoints: string[] = ['https://www.google.com', 'https://appleid.apple.com'],
    timeoutMs = 3000
  ): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      const connectivityTests = endpoints.map(async (endpoint) => {
        try {
          const response = await firstValueFrom(
            this.httpService.head(endpoint).pipe(
              timeout(timeoutMs),
              catchError(error => of({ status: 0, error: error.message }))
            )
          );
          
          return {
            endpoint,
            status: response.status >= 200 && response.status < 400 ? 'up' : 'down',
            httpStatus: response.status,
            error: response.error || null,
          };
        } catch (error) {
          return {
            endpoint,
            status: 'down',
            error: error.message,
          };
        }
      });

      const results = await Promise.all(connectivityTests);
      const responseTime = Date.now() - startTime;
      
      const healthyCount = results.filter(r => r.status === 'up').length;
      const overallStatus = healthyCount > 0; // At least one endpoint should be reachable

      const details = {
        status: overallStatus ? 'up' : 'down',
        responseTime: `${responseTime}ms`,
        endpoints: results,
        summary: {
          total: endpoints.length,
          healthy: healthyCount,
          unhealthy: endpoints.length - healthyCount,
        },
        timestamp: new Date().toISOString(),
      };

      const result = this.getStatus(key, overallStatus, details);

      if (!overallStatus) {
        throw new HealthCheckError('Network connectivity health check failed', result);
      }

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('Network connectivity health check failed', result);
    }
  }

  /**
   * Comprehensive external services health check
   * 
   * @param key - Health check identifier
   * @returns Comprehensive health check result for all external dependencies
   */
  async checkAllExternalServices(key: string): Promise<HealthIndicatorResult> {
    const startTime = Date.now();
    
    try {
      const [oauthResult, dnsResult, networkResult] = await Promise.allSettled([
        this.checkAllOAuthServices('oauth_services', 3000),
        this.checkDNSResolution('dns_resolution'),
        this.checkNetworkConnectivity('network_connectivity', undefined, 2000),
      ]);

      const responseTime = Date.now() - startTime;
      
      const oauthStatus = oauthResult.status === 'fulfilled';
      const dnsStatus = dnsResult.status === 'fulfilled';
      const networkStatus = networkResult.status === 'fulfilled';
      
      const healthyServices = [oauthStatus, dnsStatus, networkStatus].filter(Boolean).length;
      const overallStatus = healthyServices >= 2; // At least 2/3 services should be healthy

      const details = {
        status: overallStatus ? 'up' : 'degraded',
        responseTime: `${responseTime}ms`,
        services: {
          oauth: {
            status: oauthStatus ? 'up' : 'down',
            error: oauthResult.status === 'rejected' ? oauthResult.reason.message : null,
          },
          dns: {
            status: dnsStatus ? 'up' : 'down',
            error: dnsResult.status === 'rejected' ? dnsResult.reason.message : null,
          },
          network: {
            status: networkStatus ? 'up' : 'down',
            error: networkResult.status === 'rejected' ? networkResult.reason.message : null,
          },
        },
        summary: {
          total: 3,
          healthy: healthyServices,
          threshold: '2/3 services must be healthy',
        },
        timestamp: new Date().toISOString(),
      };

      const result = this.getStatus(key, overallStatus, details);

      if (!overallStatus) {
        throw new HealthCheckError('External services health check failed', result);
      }

      return result;
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      const result = this.getStatus(key, false, {
        status: 'down',
        error: error.message,
        responseTime: `${responseTime}ms`,
        timestamp: new Date().toISOString(),
      });

      throw new HealthCheckError('External services health check failed', result);
    }
  }
}