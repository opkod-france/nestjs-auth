import { describe, it, expect, vi } from 'vitest';
import { Reflector } from '@nestjs/core';
import { ExecutionContext } from '@nestjs/common';
import { JwtAuthGuard } from '../src/guards/jwt-auth.guard';

describe('JwtAuthGuard', () => {
  const reflector = new Reflector();
  const guard = new JwtAuthGuard(reflector);

  function createMockContext(): ExecutionContext {
    return {
      getHandler: vi.fn(),
      getClass: vi.fn(),
      switchToHttp: vi.fn().mockReturnValue({
        getRequest: vi.fn().mockReturnValue({}),
        getResponse: vi.fn().mockReturnValue({}),
        getNext: vi.fn(),
      }),
      getType: vi.fn().mockReturnValue('http'),
      getArgs: vi.fn().mockReturnValue([{}, {}, vi.fn()]),
      getArgByIndex: vi.fn(),
      switchToRpc: vi.fn(),
      switchToWs: vi.fn(),
    } as unknown as ExecutionContext;
  }

  it('should allow access for @Public() routes', () => {
    const context = createMockContext();
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(true);

    const result = guard.canActivate(context);
    expect(result).toBe(true);
  });

  it('should delegate to passport for non-public routes', async () => {
    const context = createMockContext();
    vi.spyOn(reflector, 'getAllAndOverride').mockReturnValue(false);

    // super.canActivate calls passport which will reject without a valid token
    const result = guard.canActivate(context);
    await expect(Promise.resolve(result)).rejects.toThrow();
  });
});
