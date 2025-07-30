import { Test, TestingModule } from '@nestjs/testing';
import { InputSanitizer } from '../input-sanitizer.service';

describe('InputSanitizer', () => {
  let service: InputSanitizer;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [InputSanitizer],
    }).compile();

    service = module.get<InputSanitizer>(InputSanitizer);
  });

  describe('String Sanitization', () => {
    it('should sanitize basic XSS attempts', () => {
      const testCases = [
        {
          input: '<script>alert("xss")</script>',
          expected: '',
        },
        {
          input: '<img src="x" onerror="alert(1)">',
          expected: '',
        },
        {
          input: 'Hello <b>World</b>!',
          expected: 'Hello World!',
        },
        {
          input: 'Test & Company',
          expected: 'Test &amp; Company',
        },
        {
          input: 'Quote "test" here',
          expected: 'Quote &quot;test&quot; here',
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(service.sanitizeString(input)).toBe(expected);
      });
    });

    it('should remove null bytes and dangerous characters', () => {
      const input = 'Test\x00String<>"\'\&';
      const result = service.sanitizeString(input);
      
      expect(result).toBe('TestString&lt;&gt;&quot;&#x27;&amp;');
      expect(result).not.toContain('\x00');
    });

    it('should trim whitespace', () => {
      const input = '  \t  Test String  \n  ';
      const result = service.sanitizeString(input);
      
      expect(result).toBe('Test String');
    });

    it('should enforce length limits', () => {
      const longInput = 'a'.repeat(100);
      const result = service.sanitizeString(longInput, 50);
      
      expect(result).toHaveLength(50);
    });

    it('should handle non-string inputs', () => {
      expect(service.sanitizeString(null as any)).toBe('');
      expect(service.sanitizeString(undefined as any)).toBe('');
      expect(service.sanitizeString(123 as any)).toBe('');
    });
  });

  describe('Email Sanitization', () => {
    it('should sanitize valid email addresses', () => {
      const testCases = [
        {
          input: 'Test@Example.COM',
          expected: 'test@example.com',
        },
        {
          input: '  user.name+tag@domain.co.uk  ',
          expected: 'user.name+tag@domain.co.uk',
        },
        {
          input: 'valid_email123@test-domain.info',
          expected: 'valid_email123@test-domain.info',
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(service.sanitizeEmail(input)).toBe(expected);
      });
    });

    it('should reject invalid email formats', () => {
      const invalidEmails = [
        'not-an-email',
        '@domain.com',
        'user@',
        'user..double.dot@domain.com',
        'user@domain',
        'user name@domain.com', // space
        'user<script>@domain.com',
      ];

      invalidEmails.forEach(email => {
        expect(service.sanitizeEmail(email)).toBe('');
      });
    });

    it('should remove dangerous characters from emails', () => {
      const maliciousEmail = 'user<script>@domain.com';
      const result = service.sanitizeEmail(maliciousEmail);
      
      expect(result).toBe('');
    });

    it('should handle non-string email inputs', () => {
      expect(service.sanitizeEmail(null as any)).toBe('');
      expect(service.sanitizeEmail(undefined as any)).toBe('');
      expect(service.sanitizeEmail(123 as any)).toBe('');
    });
  });

  describe('URL Sanitization', () => {
    it('should sanitize valid URLs', () => {
      const testCases = [
        {
          input: 'https://example.com/path?param=value',
          expected: 'https://example.com/path?param=value',
        },
        {
          input: 'http://localhost:3000/api/test',
          expected: 'http://localhost:3000/api/test',
        },
        {
          input: '  https://example.com/  ',
          expected: 'https://example.com/',
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(service.sanitizeUrl(input)).toBe(expected);
      });
    });

    it('should reject dangerous URL schemes', () => {
      const dangerousUrls = [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'vbscript:msgbox(1)',
        'file:///etc/passwd',
        'ftp://example.com/file.txt',
      ];

      dangerousUrls.forEach(url => {
        expect(service.sanitizeUrl(url)).toBe('');
      });
    });

    it('should handle malformed URLs', () => {
      const malformedUrls = [
        'not-a-url',
        'http://',
        'https://',
        '',
        'ht tp://example.com',
      ];

      malformedUrls.forEach(url => {
        expect(service.sanitizeUrl(url)).toBe('');
      });
    });
  });

  describe('File Name Sanitization', () => {
    it('should sanitize dangerous file names', () => {
      const testCases = [
        {
          input: '../../../etc/passwd',
          expected: 'etcpasswd',
        },
        {
          input: 'file<script>alert(1)</script>.txt',
          expected: 'filescriptalert1scripttxt',
        },
        {
          input: 'document.pdf',
          expected: 'documentpdf',
        },
        {
          input: 'file|with|pipes.doc',
          expected: 'filewithpipesdoc',
        },
        {
          input: '...hidden.file',
          expected: 'hiddenfile',
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(service.sanitizeFileName(input)).toBe(expected);
      });
    });

    it('should handle Windows reserved names', () => {
      const reservedNames = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1'];
      
      reservedNames.forEach(name => {
        const result = service.sanitizeFileName(`${name}.txt`);
        expect(result).toBe(`file_${name}txt`);
      });
    });

    it('should limit file name length', () => {
      const longName = 'a'.repeat(300);
      const result = service.sanitizeFileName(longName);
      
      expect(result.length).toBeLessThanOrEqual(255);
    });

    it('should handle empty or invalid file names', () => {
      expect(service.sanitizeFileName('')).toBe('untitled');
      expect(service.sanitizeFileName('...')).toBe('untitled');
      expect(service.sanitizeFileName(null as any)).toBe('untitled');
    });
  });

  describe('JSON Sanitization', () => {
    it('should sanitize string values in JSON', () => {
      const input = {
        name: '<script>alert(1)</script>',
        email: 'test@example.com',
        description: 'Safe content',
      };

      const result = service.sanitizeJson(input);
      
      expect(result.name).toBe('');
      expect(result.email).toBe('test@example.com');
      expect(result.description).toBe('Safe content');
    });

    it('should preserve non-string values', () => {
      const input = {
        name: 'John',
        age: 30,
        active: true,
        score: null,
        tags: ['tag1', 'tag2'],
      };

      const result = service.sanitizeJson(input);
      
      expect(result.name).toBe('John');
      expect(result.age).toBe(30);
      expect(result.active).toBe(true);
      expect(result.score).toBeNull();
      expect(result.tags).toEqual(['tag1', 'tag2']);
    });

    it('should filter keys based on allowlist', () => {
      const input = {
        name: 'John',
        email: 'john@example.com',
        password: 'secret',
        token: 'abc123',
      };

      const result = service.sanitizeJson(input, ['name', 'email']);
      
      expect(result).toHaveProperty('name', 'John');
      expect(result).toHaveProperty('email', 'john@example.com');
      expect(result).not.toHaveProperty('password');
      expect(result).not.toHaveProperty('token');
    });

    it('should handle nested objects and arrays', () => {
      const input = {
        user: {
          name: '<script>alert(1)</script>',
          profile: {
            bio: 'Safe content',
          },
        },
        items: [
          { title: '<img onerror="alert(1)">' },
          { title: 'Safe title' },
        ],
      };

      const result = service.sanitizeJson(input);
      
      expect(result.user.name).toBe('');
      expect(result.user.profile.bio).toBe('Safe content');
      expect(result.items[0].title).toBe('');
      expect(result.items[1].title).toBe('Safe title');
    });
  });

  describe('SQL Input Sanitization', () => {
    it('should remove dangerous SQL patterns', () => {
      const testCases = [
        {
          input: "'; DROP TABLE users; --",
          expected: '',
        },
        {
          input: 'SELECT * FROM users',
          expected: '',
        },
        {
          input: "user' OR 1=1 --",
          expected: 'user',
        },
        {
          input: 'UNION SELECT password FROM users',
          expected: 'password FROM users',
        },
        {
          input: 'safe_username_123',
          expected: 'safe_username_123',
        },
      ];

      testCases.forEach(({ input, expected }) => {
        expect(service.sanitizeSqlInput(input)).toBe(expected);
      });
    });

    it('should remove SQL comments', () => {
      const inputs = [
        "test -- comment",
        "test /* comment */",
        "test/* multi\nline */",
      ];

      inputs.forEach(input => {
        const result = service.sanitizeSqlInput(input);
        expect(result).not.toContain('--');
        expect(result).not.toContain('/*');
        expect(result).not.toContain('*/');
      });
    });
  });

  describe('Input Validation', () => {
    it('should detect XSS patterns', () => {
      const xssInputs = [
        '<script>alert(1)</script>',
        'javascript:alert(1)',
        '<img onerror="alert(1)">',
        '<iframe src="javascript:alert(1)">',
      ];

      xssInputs.forEach(input => {
        const result = service.validateInput(input);
        expect(result.isValid).toBe(false);
        expect(result.threats).toContain('XSS');
      });
    });

    it('should detect SQL injection patterns', () => {
      const sqlInputs = [
        "'; DROP TABLE users; --",
        'UNION SELECT * FROM passwords',
        "admin' OR 1=1 --",
        'SELECT * FROM users WHERE id = 1',
      ];

      sqlInputs.forEach(input => {
        const result = service.validateInput(input);
        expect(result.isValid).toBe(false);
        expect(result.threats).toContain('SQL_INJECTION');
      });
    });

    it('should detect path traversal attempts', () => {
      const pathInputs = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\',
        '/etc/shadow',
        '\\windows\\system32\\cmd.exe',
      ];

      pathInputs.forEach(input => {
        const result = service.validateInput(input);
        expect(result.isValid).toBe(false);
        expect(result.threats).toContain('PATH_TRAVERSAL');
      });
    });

    it('should detect command injection patterns', () => {
      const commandInputs = [
        'test; rm -rf /',
        'input | cat /etc/passwd',
        'file && shutdown -h now',
        'test`whoami`',
      ];

      commandInputs.forEach(input => {
        const result = service.validateInput(input);
        expect(result.isValid).toBe(false);
        expect(result.threats).toContain('COMMAND_INJECTION');
      });
    });

    it('should validate safe input', () => {
      const safeInputs = [
        'normal text content',
        'user@example.com',
        'Product Name 123',
        'Description with (parentheses) and spaces',
      ];

      safeInputs.forEach(input => {
        const result = service.validateInput(input);
        expect(result.isValid).toBe(true);
        expect(result.threats).toHaveLength(0);
      });
    });

    it('should handle multiple threat types', () => {
      const input = '<script>alert(1)</script>; DROP TABLE users; ../../../etc/passwd';
      const result = service.validateInput(input);
      
      expect(result.isValid).toBe(false);
      expect(result.threats.length).toBeGreaterThan(1);
      expect(result.threats).toContain('XSS');
      expect(result.threats).toContain('SQL_INJECTION');
      expect(result.threats).toContain('PATH_TRAVERSAL');
    });
  });

  describe('Header Sanitization', () => {
    it('should sanitize and filter request headers', () => {
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer token123',
        'User-Agent': 'Mozilla/5.0',
        'X-Custom-Header': 'should-be-removed',
        'X-Forwarded-For': '192.168.1.1',
        'Cookie': 'should-be-removed',
      };

      const result = service.sanitizeHeaders(headers);
      
      expect(result).toHaveProperty('content-type', 'application/json');
      expect(result).toHaveProperty('authorization', 'Bearer token123');
      expect(result).toHaveProperty('user-agent', 'Mozilla/5.0');
      expect(result).toHaveProperty('x-forwarded-for', '192.168.1.1');
      expect(result).not.toHaveProperty('x-custom-header');
      expect(result).not.toHaveProperty('cookie');
    });

    it('should sanitize header values', () => {
      const headers = {
        'User-Agent': '<script>alert(1)</script>Mozilla',
        'Accept': 'text/html,application/json',
      };

      const result = service.sanitizeHeaders(headers);
      
      expect(result['user-agent']).toBe('Mozilla');
      expect(result['accept']).toBe('text/html,application/json');
    });

    it('should limit header value length', () => {
      const headers = {
        'User-Agent': 'a'.repeat(2000),
      };

      const result = service.sanitizeHeaders(headers);
      
      expect(result['user-agent'].length).toBeLessThanOrEqual(1000);
    });
  });

  describe('CSP Nonce Generation', () => {
    it('should generate unique CSP nonces', () => {
      const nonce1 = service.generateCSPNonce();
      const nonce2 = service.generateCSPNonce();
      
      expect(nonce1).toHaveLength(16);
      expect(nonce2).toHaveLength(16);
      expect(nonce1).not.toBe(nonce2);
      expect(nonce1).toMatch(/^[A-Za-z0-9]+$/);
    });
  });
});