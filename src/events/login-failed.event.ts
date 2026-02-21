export class LoginFailedEvent {
  constructor(
    public readonly email: string,
    public readonly reason: 'user_not_found' | 'invalid_password',
  ) {}
}
