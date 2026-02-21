export interface AuthModuleOptions {
  jwt: {
    secret: string;
    accessExpiresIn?: string | number;
    refreshExpiresIn?: string | number;
  };
  hash?: {
    rounds?: number;
  };
}
