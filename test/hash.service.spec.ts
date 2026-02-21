import { describe, it, expect } from 'vitest';
import { BcryptjsHashService } from '../src/services/hash.service';

describe('BcryptjsHashService', () => {
  const service = new BcryptjsHashService(4); // Low rounds for test speed

  it('should hash a string', async () => {
    const hashed = await service.hash('password123');
    expect(hashed).toBeDefined();
    expect(hashed).not.toBe('password123');
  });

  it('should return true for matching password', async () => {
    const hashed = await service.hash('password123');
    const result = await service.compare('password123', hashed);
    expect(result).toBe(true);
  });

  it('should return false for non-matching password', async () => {
    const hashed = await service.hash('password123');
    const result = await service.compare('wrong', hashed);
    expect(result).toBe(false);
  });
});
