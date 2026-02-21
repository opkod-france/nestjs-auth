import { Injectable } from '@nestjs/common';

export abstract class HashService {
  abstract hash(data: string): Promise<string>;
  abstract compare(data: string, hash: string): Promise<boolean>;
}

@Injectable()
export class BcryptjsHashService extends HashService {
  private bcryptjs: typeof import('bcryptjs') | null = null;
  private readonly rounds: number;

  constructor(rounds = 10) {
    super();
    this.rounds = rounds;
  }

  private async getBcryptjs() {
    if (!this.bcryptjs) {
      this.bcryptjs = await import('bcryptjs');
    }
    return this.bcryptjs;
  }

  async hash(data: string): Promise<string> {
    const bcrypt = await this.getBcryptjs();
    return bcrypt.hash(data, this.rounds);
  }

  async compare(data: string, hashed: string): Promise<boolean> {
    const bcrypt = await this.getBcryptjs();
    return bcrypt.compare(data, hashed);
  }
}
