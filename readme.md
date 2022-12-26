# NestJS Authentication Library Proof of Concept

## Features
- Automatically authentication routers generation.
- Local user login (email + password).
- Local user register.
- JWT authentication.

## Supported routers
- POST /auth/login
- POST /auth/register
- GET /auth/me

## Example implementation
- Library code: `/src/auth`
- User entity: `/src/users/user.entity.ts`

## There are two working strategies for this module
- DB Strategy
- Service Strategy

### DB Strategy
  - Pros:
    - Easy to implement.
    - Automatically create repository for user entity.
    - Suitable for small projects or projects that don't have a complex authentication logic.
  - Cons:
    - The database is dependent on adapters supported by nest/typeorm.
    - Not suitable for large projects.

### Service Strategy
  - Pros:
    - Flexible customization, not heavily dependent on the framework.
  - Cons:
    - Harder to implement.
    - Suitable for large projects or projects that have a complex authentication logic.

## Usage:

#### Import the user entity and the auth module
```typescript
import { UserEntity } from './user/user.entity';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';
```

### DB Strategy

#### Register the authentication module: app.module.ts
```typescript
AuthModule.register<UserEntity>(UserEntity);
```

#### Available options
```typescript
// Custom DB fields for checking local user login
public identityFields: string[] = ['username', 'email'];
public passwordField?: string = 'password';
```

### Service Strategy
#### Import user module and user service:
```typescript
import { UserModule } from './user/user.module';
import { UserService } from './user/user.service';
```

### Register the authentication module: app.module.ts
```typescript
AuthModule.register<UserEntity, JwtPayload>(
  UserModule,
  UserService,
  UserEntity
)
```

#### Available options
```typescript
// Custom user register method
async register(data: RegisterDTO) {
  const user = this.userRepository.create(data);
  return this.userRepository.save(user);
}

// Custom user login method
async checkLogin(username: string, password: string): Promise<UserEntity> {
  const user = await this.userRepository.findOne({
    where: [{ username }, { email: username }],
  });

  if (!user || user.password !== password) {
    throw new Error('Invalid credentials');
  }

  return user;
}
```

**Note:** Because the `userRepository` will be injected into the `UserService` automatically, it must be exported from the `userModule`:
```diff
@Module({
  imports: [TypeOrmModule.forFeature([UserEntity])],
  providers: [UserService, ],
  exports: [
    UserService,
+   TypeOrmModule.forFeature([UserEntity]),
  ],
  controllers: [UserController],
})
export class UserModule {}
```

## Auth Module Signatures
```typescript
static register<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayload extends ObjectLiteral = ObjectLiteral
>(
  userEntity: EntityTarget<Entity>,
  userModule?: NestModule,
  userService?: typeof AuthUserService<Entity, JwtPayload>,
  jwtOptions: JwtModuleOptions = {},
): DynamicModule
```

## JWT methods:
```typescript
// Custom request body fields for local login
localStrategyOptions(): IStrategyOptions {
  return {
    usernameField: 'username',
    passwordField: 'password',
  };
}

// Custom Jwt payload, default is { sub: { ...user } }
async createJwtSignerPayload(user: UserEntity) {
  return {
    sub: {
      id: user.id,
      username: user.username,
      email: user.email,
    }
  };
}

// Custom Jwt validator, default is { ...user }
async jwtValidator(payload: JwtPayload) {
  return this.userRepository.findOneBy({ id: payload.sub.id });
}
```

## Roadmap
- [x] Base module with local strategy.
- [ ] Customizable routers.
- [ ] Session authentication.
- [ ] Add more authentication providers (Google, Facebook, Twitter, Github, etc.)
- [ ] Add more routers (Forgot password, Reset password, etc.)
