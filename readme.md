# NestJS Authentication Library Proof of Concept

## Features
- Automatically authentication routers generation.
- Local user register/login (email + password).
- Social authentication (Google, Facebook, Twitter, Github, etc.).
- JWT authentication.

## Supported routers
- POST  /login
- POST  /register
- GET   /confirm
- POST  /forgot-password
- GET   /forgot-password
- POST  /change-password
- GET   /logout
- POST  /refresh
- GET   /me
- GET   /social/sign-in/:provider
- GET   /social/sign-in/:provider/callback

## Usage:

```typescript
import { AuthModule } from '@tech-standard-nest-auth';

@Module({
  imports: [
    createTypeOrmMOdule([UserEntity]),
    AuthModule.register<UserEntity>({
      authKey: 'auth_key_with_32_bytes_randomly_',
      typeormUserEntity: UserEntity,
    }),
  ],
})
export class AppModule { }
```

## Examples:
Check the `examples` folder.

## Available options:
```typescript
export interface AuthModuleOptions {
  authKey: string;                            // must be at least 32 characters
  typeormUserEntity?: EntityTarget            // from typeorm;
  imports?: NestModule[];                     // from nest
  userService?: typeof UserAuthServiceType;
  config?: AuthModuleConfig;
}

// Strategy from @types/passport
export interface AuthModuleConfig {
  disableApi?: boolean;
  enableRefreshTokenRotation?: boolean;
  passwordHashSecret?: string;
  passportStrategies?: Strategy[];
  jwt?: JwtOptions;
  recovery?: {
    tokenExpiresIn?: number;  //seconds
    tokenSecret?: string;     // must be at least 32 characters
  };
}

// JwtModuleOptions and JwtSignOptions from @nestjs/jwt
export interface JwtOptions extends JwtModuleOptions {
  jwtFromRequest?: () => JwtFromRequestFunction;
  refresh?: JwtSignOptions;
}
```

## Roadmap
- [x] Base module with local strategy.
- [x] Refresh token.
- [x] Custom hash password function.
- [x] Avaibility to use custom user controller.
- [x] Add more authentication providers (Google, Facebook, Twitter, Github, etc.)
- [x] Add more features (Forgot password, Reset password, etc.)
- [ ] Session authentication.
- [ ] Customizable routers.
