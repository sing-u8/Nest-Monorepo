import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { Request } from 'express';
import * as crypto from 'crypto';
import { TLSSocket } from 'tls';

/**
 * mTLS (Mutual TLS) Authentication Guard
 * 
 * Validates client certificates for mutual TLS authentication.
 * This guard verifies that:
 * 1. A valid client certificate is presented
 * 2. The certificate is signed by a trusted CA
 * 3. The certificate is not expired
 * 4. The certificate contains required attributes
 * 
 * The validated certificate information is attached to the request
 * object for use by controllers and other components.
 */
@Injectable()
export class MTLSAuthGuard implements CanActivate {
  private readonly logger = new Logger(MTLSAuthGuard.name);

  // Configuration for certificate validation
  private readonly config = {
    // Required certificate attributes
    requiredAttributes: ['CN', 'O'], // Common Name and Organization
    
    // Certificate validation options
    allowSelfSigned: process.env.NODE_ENV === 'development',
    
    // Maximum certificate chain depth
    maxChainDepth: 3,
    
    // Certificate purposes that are allowed
    allowedPurposes: ['serverAuth', 'clientAuth'],
    
    // Grace period for certificate expiration (in milliseconds)
    expirationGracePeriod: 5 * 60 * 1000, // 5 minutes
  };

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    
    try {
      // Check if the connection is using TLS
      const socket = request.socket;
      if (!this.isTLSSocket(socket)) {
        this.logger.warn('Request not using TLS connection');
        throw new UnauthorizedException('mTLS connection required');
      }

      // Get client certificate from TLS socket
      const clientCert = this.extractClientCertificate(socket);
      if (!clientCert) {
        this.logger.warn('No client certificate provided in mTLS connection');
        throw new UnauthorizedException('Client certificate required');
      }

      // Validate the certificate
      await this.validateCertificate(clientCert, socket);

      // Extract certificate information
      const certInfo = this.extractCertificateInfo(clientCert);

      // Attach certificate information to request
      (request as any).certificate = certInfo;
      (request as any).user = {
        id: certInfo.subject.CN,
        organization: certInfo.subject.O,
        certificateFingerprint: certInfo.fingerprint,
        authenticationType: 'mtls',
      };

      this.logger.debug(`mTLS authentication successful for: ${certInfo.subject.CN}`);
      return true;

    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      this.logger.error('mTLS authentication error', {
        error: error.message,
        stack: error.stack,
      });
      
      throw new UnauthorizedException('mTLS authentication failed');
    }
  }

  /**
   * Check if the socket is a TLS socket
   */
  private isTLSSocket(socket: any): socket is TLSSocket {
    return socket && typeof socket.getPeerCertificate === 'function';
  }

  /**
   * Extract client certificate from TLS socket
   */
  private extractClientCertificate(socket: TLSSocket): any | null {
    try {
      const cert = socket.getPeerCertificate(true);
      
      // Check if certificate exists and is not empty
      if (!cert || Object.keys(cert).length === 0) {
        return null;
      }

      return cert;
    } catch (error) {
      this.logger.warn('Failed to extract client certificate', { error: error.message });
      return null;
    }
  }

  /**
   * Validate the client certificate
   */
  private async validateCertificate(certificate: any, socket: TLSSocket): Promise<void> {
    // Check if certificate is authorized by TLS layer
    if (!socket.authorized) {
      const error = socket.authorizationError;
      this.logger.warn('Certificate not authorized by TLS layer', { error });
      
      // Allow specific errors in development mode
      if (this.config.allowSelfSigned && error === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
        this.logger.debug('Allowing self-signed certificate in development mode');
      } else {
        throw new UnauthorizedException(`Certificate validation failed: ${error}`);
      }
    }

    // Validate certificate expiration
    this.validateCertificateExpiration(certificate);

    // Validate required certificate attributes
    this.validateCertificateAttributes(certificate);

    // Validate certificate chain depth
    this.validateCertificateChain(certificate);

    // Validate certificate purposes
    this.validateCertificatePurposes(certificate);
  }

  /**
   * Validate certificate expiration with grace period
   */
  private validateCertificateExpiration(certificate: any): void {
    const now = new Date();
    const validFrom = new Date(certificate.valid_from);
    const validTo = new Date(certificate.valid_to);

    // Check if certificate is not yet valid
    if (now < validFrom) {
      throw new UnauthorizedException('Certificate is not yet valid');
    }

    // Check if certificate is expired (with grace period)
    const expirationWithGrace = new Date(validTo.getTime() + this.config.expirationGracePeriod);
    if (now > expirationWithGrace) {
      throw new UnauthorizedException('Certificate has expired');
    }

    // Log warning if certificate expires soon (within 30 days)
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    if (validTo < thirtyDaysFromNow) {
      this.logger.warn('Certificate expires soon', {
        subject: certificate.subject.CN,
        expiresAt: validTo.toISOString(),
      });
    }
  }

  /**
   * Validate required certificate attributes
   */
  private validateCertificateAttributes(certificate: any): void {
    const subject = certificate.subject;
    
    for (const attr of this.config.requiredAttributes) {
      if (!subject[attr]) {
        throw new UnauthorizedException(`Certificate missing required attribute: ${attr}`);
      }
    }

    // Validate Common Name format (basic validation)
    if (subject.CN) {
      if (typeof subject.CN !== 'string' || subject.CN.trim().length === 0) {
        throw new UnauthorizedException('Invalid Common Name in certificate');
      }
    }

    // Validate Organization if present
    if (subject.O) {
      if (typeof subject.O !== 'string' || subject.O.trim().length === 0) {
        throw new UnauthorizedException('Invalid Organization in certificate');
      }
    }
  }

  /**
   * Validate certificate chain depth
   */
  private validateCertificateChain(certificate: any): void {
    let chainDepth = 0;
    let currentCert = certificate;

    while (currentCert && chainDepth < this.config.maxChainDepth) {
      chainDepth++;
      currentCert = currentCert.issuerCertificate;
      
      // Break if we've reached the root (self-signed)
      if (currentCert === certificate) {
        break;
      }
    }

    if (chainDepth >= this.config.maxChainDepth) {
      throw new UnauthorizedException('Certificate chain too deep');
    }
  }

  /**
   * Validate certificate purposes/extensions
   */
  private validateCertificatePurposes(certificate: any): void {
    // Check if certificate has the required purposes
    // This is a simplified check - in production, you might want more sophisticated validation
    if (certificate.ext_key_usage) {
      const purposes = certificate.ext_key_usage;
      const hasValidPurpose = this.config.allowedPurposes.some(purpose => 
        purposes.includes(purpose)
      );

      if (!hasValidPurpose) {
        throw new UnauthorizedException('Certificate does not have valid purposes');
      }
    }
  }

  /**
   * Extract useful information from the certificate
   */
  private extractCertificateInfo(certificate: any): any {
    const fingerprint = this.calculateCertificateFingerprint(certificate);
    
    return {
      subject: {
        CN: certificate.subject.CN,
        O: certificate.subject.O,
        OU: certificate.subject.OU,
        C: certificate.subject.C,
        ST: certificate.subject.ST,
        L: certificate.subject.L,
      },
      issuer: {
        CN: certificate.issuer.CN,
        O: certificate.issuer.O,
        OU: certificate.issuer.OU,
        C: certificate.issuer.C,
      },
      serialNumber: certificate.serialNumber,
      fingerprint,
      validFrom: certificate.valid_from,
      validTo: certificate.valid_to,
      algorithm: certificate.algorithm,
      keyUsage: certificate.ext_key_usage,
      subjectAltName: certificate.subjectaltname,
    };
  }

  /**
   * Calculate SHA-256 fingerprint of the certificate
   */
  private calculateCertificateFingerprint(certificate: any): string {
    try {
      // Use the raw certificate data if available
      const certData = certificate.raw || certificate.der;
      if (certData) {
        return crypto.createHash('sha256').update(certData).digest('hex').toUpperCase();
      }

      // Fallback: use certificate fingerprint if available
      if (certificate.fingerprint) {
        return certificate.fingerprint.replace(/:/g, '').toUpperCase();
      }

      // Last resort: create fingerprint from subject and serial number
      const certString = `${certificate.subject.CN}-${certificate.serialNumber}`;
      return crypto.createHash('sha256').update(certString).digest('hex').toUpperCase();
    } catch (error) {
      this.logger.warn('Failed to calculate certificate fingerprint', { error: error.message });
      return 'UNKNOWN';
    }
  }

  /**
   * Get certificate information from request (for use in controllers)
   */
  static getCertificateInfo(request: Request): any | null {
    return (request as any).certificate || null;
  }

  /**
   * Get certificate fingerprint from request (for use in controllers)
   */
  static getCertificateFingerprint(request: Request): string | null {
    const certInfo = MTLSAuthGuard.getCertificateInfo(request);
    return certInfo?.fingerprint || null;
  }

  /**
   * Get certificate subject from request (for use in controllers)
   */
  static getCertificateSubject(request: Request): any | null {
    const certInfo = MTLSAuthGuard.getCertificateInfo(request);
    return certInfo?.subject || null;
  }
}