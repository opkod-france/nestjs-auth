import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserIdentity } from '../interfaces/user-identity.interface';

export const CurrentUser = createParamDecorator(
  (data: keyof UserIdentity | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest<{ user: UserIdentity }>();
    const user = request.user;
    return data ? user?.[data] : user;
  },
);
