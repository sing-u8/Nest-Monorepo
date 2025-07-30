import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Observable } from 'rxjs';
import * as crypto from 'crypto';

export interface MtlsAuthenticatedClient {
  certificateSubject: string;
  certificateIssuer: string;
  certificateSerial: string;
  certificateFingerprint: string;
  certificateValid: boolean;
  clientId?: string;
}

/**
 * mTLS (Mutual TLS) Authentication Guard
 * Validates client certificates for secure service-to-service communication
 */
@Injectable()
export class MtlsAuthGuard implements CanActivate {
  private readonly logger = new Logger(MtlsAuthGuard.name);
  private readonly trustedCAs: string[];
  private readonly allowedSubjects: string[];
  private readonly requireClientCert: boolean;

  constructor(private readonly configService: ConfigService) {
    this.trustedCAs = this.configService.get<string[]>('auth.mtls.trustedCAs', []);
    this.allowedSubjects = this.configService.get<string[]>('auth.mtls.allowedSubjects', []);
    this.requireClientCert = this.configService.get<boolean>('auth.mtls.requireClientCert', true);
  }

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    
    // Check if client certificate is present
    const clientCert = this.extractClientCertificate(request);
    
    if (!clientCert && this.requireClientCert) {
      this.logger.warn('No client certificate provided');
      throw new UnauthorizedException('Client certificate required');
    }

    if (!clientCert) {
      // If client cert is not required and not provided, allow access
      return true;
    }

    try {
      // Validate client certificate
      const validationResult = this.validateClientCertificate(clientCert);
      
      if (!validationResult.certificateValid) {
        this.logger.warn(
          `Invalid client certificate - Subject: ${validationResult.certificateSubject}, ` +
          `Issuer: ${validationResult.certificateIssuer}`,
        );
        throw new UnauthorizedException('Invalid client certificate');
      }

      // Check if subject is in allowed list
      if (this.allowedSubjects.length > 0) {
        const isAllowed = this.allowedSubjects.some(subject => 
          validationResult.certificateSubject.includes(subject)
        );
        
        if (!isAllowed) {
          this.logger.warn(
            `Client certificate subject not allowed - Subject: ${validationResult.certificateSubject}`,
          );
          throw new UnauthorizedException('Client certificate not authorized');
        }
      }

      // Attach client info to request
      request.mtlsClient = validationResult;

      this.logger.debug(
        `mTLS authentication successful - Subject: ${validationResult.certificateSubject}, ` +
        `Serial: ${validationResult.certificateSerial}`,
      );

      return true;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      
      this.logger.error('Error validating client certificate', error.stack);
      throw new UnauthorizedException('Certificate validation failed');
    }
  }

  /**
   * Extract client certificate from request
   */
  private extractClientCertificate(request: any): any {
    // In Express with client certificate verification enabled
    if (request.connection?.getPeerCertificate) {
      return request.connection.getPeerCertificate();
    }

    // Alternative: Certificate might be forwarded in headers by reverse proxy
    const certHeader = request.headers['x-client-cert'];
    if (certHeader) {
      return this.parseCertificateFromHeader(certHeader);
    }

    // For testing/development with certificate in custom header
    const testCert = request.headers['x-test-client-cert'];
    if (testCert && process.env.NODE_ENV !== 'production') {
      return this.parseCertificateFromHeader(testCert);
    }

    return null;
  }

  /**
   * Validate client certificate
   */
  private validateClientCertificate(cert: any): MtlsAuthenticatedClient {
    const now = new Date();
    
    // Basic certificate structure validation
    if (!cert.subject || !cert.issuer || !cert.serialNumber) {
      return {
        certificateSubject: '',
        certificateIssuer: '',
        certificateSerial: '',
        certificateFingerprint: '',
        certificateValid: false,
      };
    }

    // Extract certificate details
    const subject = this.formatDistinguishedName(cert.subject);
    const issuer = this.formatDistinguishedName(cert.issuer);
    const serial = cert.serialNumber;
    const fingerprint = cert.fingerprint || this.calculateFingerprint(cert);

    // Check certificate validity period
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const isValidPeriod = now >= validFrom && now <= validTo;

    // Check if certificate is self-signed (not allowed for mTLS)
    const isSelfSigned = subject === issuer;
    if (isSelfSigned) {
      this.logger.warn('Self-signed certificate detected');
      return {
        certificateSubject: subject,
        certificateIssuer: issuer,
        certificateSerial: serial,
        certificateFingerprint: fingerprint,
        certificateValid: false,
      };
    }

    // Verify certificate chain if CA list is configured
    let isChainValid = true;
    if (this.trustedCAs.length > 0) {
      isChainValid = this.verifyCertificateChain(cert, this.trustedCAs);
    }

    // Extract client ID from certificate subject (if present)
    const clientId = this.extractClientIdFromSubject(subject);

    return {
      certificateSubject: subject,
      certificateIssuer: issuer,
      certificateSerial: serial,
      certificateFingerprint: fingerprint,
      certificateValid: isValidPeriod && isChainValid && !isSelfSigned,
      clientId,
    };
  }

  /**
   * Parse certificate from header (base64 encoded)
   */
  private parseCertificateFromHeader(certHeader: string): any {
    try {
      // Remove URL encoding if present
      const decodedCert = decodeURIComponent(certHeader);
      
      // Parse certificate (simplified for example)
      // In production, use proper X.509 certificate parsing library
      const certData = Buffer.from(decodedCert, 'base64').toString();
      
      // Extract basic info from PEM format
      const subjectMatch = certData.match(/Subject: (.+)/);
      const issuerMatch = certData.match(/Issuer: (.+)/);
      const serialMatch = certData.match(/Serial Number: (.+)/);
      
      return {
        subject: subjectMatch ? this.parseDistinguishedName(subjectMatch[1]) : {},
        issuer: issuerMatch ? this.parseDistinguishedName(issuerMatch[1]) : {},
        serialNumber: serialMatch ? serialMatch[1] : '',
        valid_from: new Date().toISOString(), // Simplified
        valid_to: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // Simplified
        fingerprint: this.calculateFingerprintFromPEM(certData),
      };
    } catch (error) {
      this.logger.error('Failed to parse certificate from header', error);
      return null;
    }
  }

  /**
   * Format distinguished name for display
   */
  private formatDistinguishedName(dn: any): string {
    if (typeof dn === 'string') {
      return dn;
    }

    const parts = [];
    if (dn.CN) parts.push(`CN=${dn.CN}`);
    if (dn.O) parts.push(`O=${dn.O}`);
    if (dn.OU) parts.push(`OU=${dn.OU}`);
    if (dn.C) parts.push(`C=${dn.C}`);
    if (dn.ST) parts.push(`ST=${dn.ST}`);
    if (dn.L) parts.push(`L=${dn.L}`);
    
    return parts.join(', ');
  }

  /**
   * Parse distinguished name string
   */
  private parseDistinguishedName(dnString: string): any {
    const dn: any = {};
    const parts = dnString.split(', ');
    
    parts.forEach(part => {
      const [key, value] = part.split('=');
      if (key && value) {
        dn[key.trim()] = value.trim();
      }
    });
    
    return dn;
  }

  /**
   * Calculate certificate fingerprint
   */
  private calculateFingerprint(cert: any): string {
    // Simplified fingerprint calculation
    const certString = JSON.stringify({
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
    });
    
    return crypto
      .createHash('sha256')
      .update(certString)
      .digest('hex')
      .toUpperCase()
      .match(/.{2}/g)
      ?.join(':') || '';
  }

  /**
   * Calculate fingerprint from PEM certificate
   */
  private calculateFingerprintFromPEM(pemCert: string): string {
    return crypto
      .createHash('sha256')
      .update(pemCert)
      .digest('hex')
      .toUpperCase()
      .match(/.{2}/g)
      ?.join(':') || '';
  }

  /**
   * Verify certificate chain against trusted CAs
   */
  private verifyCertificateChain(cert: any, trustedCAs: string[]): boolean {
    // Simplified chain verification
    // In production, use proper X.509 certificate chain validation
    const issuer = this.formatDistinguishedName(cert.issuer);
    
    return trustedCAs.some(ca => issuer.includes(ca));
  }

  /**
   * Extract client ID from certificate subject
   */
  private extractClientIdFromSubject(subject: string): string | undefined {
    // Look for CN (Common Name) which often contains the client identifier
    const cnMatch = subject.match(/CN=([^,]+)/);
    if (cnMatch && cnMatch[1]) {
      return cnMatch[1];
    }
    
    // Look for OU (Organizational Unit) as fallback
    const ouMatch = subject.match(/OU=([^,]+)/);
    if (ouMatch && ouMatch[1]) {
      return ouMatch[1];
    }
    
    return undefined;
  }
}