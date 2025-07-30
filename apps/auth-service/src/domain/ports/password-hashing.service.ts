export interface PasswordHashingService {
  hash(password: string): Promise<string>;
  compare(password: string, hashedPassword: string): Promise<boolean>;
  isValidPasswordFormat(password: string): boolean;
  generateSalt(): Promise<string>;
}