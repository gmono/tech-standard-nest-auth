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
- GET /auth/refresh

## Example implementation
- Register module: `/src/app.module.ts`
- Library code: `/src/auth`
- User entity: `/src/user/user.entity.ts`
- Custom user authentication service: `/src/user/user.auth.service.ts`

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

### Import the user entity and the auth module
```typescript
import { UserEntity } from './user/user.entity';
import { AuthModule } from './auth/auth.module';
import { AppController } from './app.controller';
import { UserAuthService, UserAuthServiceWithDataSource } from './user/user.auth.service';
```

### DB Strategy

#### Register the authentication module: app.module.ts
```typescript
// common options
{
  enableRefreshTokenRotation: true,
  passwordHashSecret: 'myPasswordSecret',
  jwt: {
    accessTokenSecretOrKey: 'myApplicationSecret',
    accessTokenExpiresIn: '20s',
  },
}
```

```typescript
import { UserEntity } from './user/user.entity';

AuthModule.register({
  typeormUserEntity: UserEntity,
  options,
});
```

#### Available options
```typescript
// Custom user ID field, default is 'id'
public IDField: string = 'id';

// Custom DB fields for checking local user login
public dbUsernameFields: string[] = ['username', 'email'];
public dbPasswordField: string = 'password';

// Custom request body fields for local login
public requestUsernameField: string = 'username';
public requestPasswordField: string = 'password';
```

### Service Strategy
#### Import user module and user service:
```typescript
import { UserAuthService, UserAuthServiceWithDataSource } from './user/user.auth.service';
```

**There are two ways to import the user authentication service:**

#### Standalone service without any dependencies injected
```typescript
@Injectable()
export class UserAuthServiceWithDataSource extends BaseUserService<UserEntity, JwtPayloadSub> {
  constructor(
    private dataSource: DataSource,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(dataSource.getRepository(UserEntity), options);
  }
}

AuthModule.register({
  userService: UserAuthServiceWithDataSource,
  options,
});
```

#### Service with dependencies injected
```typescript
@Injectable()
export class UserAuthService extends BaseUserService<UserEntity, JwtPayloadSub> {
  constructor(
    @InjectRepository(UserEntity)
    userRepository: Repository<UserEntity>,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) {
    super(userRepository, options);
  }
}

AuthModule.register({
  userService: UserAuthService,
  imports: [TypeOrmModule.forFeature([UserEntity])],
  options,
});
```

#### Available options
```typescript
// Custom hash password function
async hashPassword(input: string): Promise<string> {
  return argon2.hash(input, {
    secret: Buffer.from(this.options.passwordHashSecret),
  });
}

// Custom verify password function
async verifyPassword(input: string, hashedPassword: string): Promise<boolean> {
  return argon2.verify(hashedPassword, input, {
    secret: Buffer.from(this.options.passwordHashSecret),
  });
}

// Transform the register response object
async onBeforeRegisterResponse(body: RegisterDTO, user: Entity) {
  return {
    // body,
    user,
  };
}

// Transform the login response object
async onBeforeLoginResponse(user: Entity, refreshToken: string, accessToken: string) {
  return {
    // user,
    refreshToken,
    accessToken,
  };
}

// Transform the refresh token response object
onBeforeRefreshTokenResponse(
  payload: JwtPayloadSub,
  user: Entity,
  refreshToken: string,
  accessToken: string,
): any {
  return {
    // payload,
    // user,
    accessToken,
    refreshToken,
  };
}

// Custom Jwt access token payload, default is { id }
async createJwtAccessTokenPayload(user: Entity): Promise<JwtPayload<JwtPayloadSub>> {
  if (!user[this.IDField]) {
    throw new Error(`${this.IDField} is not defined in user object: ${JSON.stringify(user)}`);
  }

  const payload = {
    sub: {
      [this.IDField]: user[this.IDField],
    }
  }

  return payload as JwtPayload;
}

// Custom Jwt refresh token payload, default is { id }
async createJwtRefreshTokenPayload(user: Entity): Promise<JwtPayload<Partial<JwtPayloadSub>>> {
  return this.createJwtAccessTokenPayload(user);
}

// Custom Jwt validator, default is { ...user }
async jwtValidator(payload: JwtPayloadSub) {
  if (!payload.sub[this.IDField]) {
    throw new Error('Invalid JWT payload');
  }

  const user = await this.userRepository.findOneBy({
    [this.IDField]: payload.sub[this.IDField]
  } as FindOptionsWhere<Entity>);

  if (!user) {
    throw new UnauthorizedException();
  }

  delete user[this.dbPasswordField];
  return user;
}

// Custom user register method
async register(data: RegisterDTO): Promise<Entity> {
  const userData = data as unknown as Entity;
  const passwordField = this.dbPasswordField as keyof Entity;
  userData[passwordField] = await this.hashPassword(userData[passwordField] as string) as Entity[keyof Entity];
  const user = this.userRepository.create(data as unknown as DeepPartial<Entity>);
  const savedUser = await this.userRepository.save(user);
  delete savedUser[passwordField];
  return savedUser;
}

// Custom user login method
async login(username: string, password: string): Promise<Entity> {
  const user = await this.userRepository.findOne({
    where: this.dbUsernameFields.map(field => ({
      [field]: username,
    })) as FindOptionsWhere<Entity>[],
  });

  const validPassword = await this.verifyPassword(password, user[this.dbPasswordField] as string);

  if (!user || !validPassword) {
    throw new UnauthorizedException();
  }

  return user;
}
```

## Roadmap
- [x] Base module with local strategy.
- [x] Refresh token.
- [x] Custom hash password function.
- [ ] Avaibility to use custom user controller.
- [ ] Session authentication.
- [ ] Add more authentication providers (Google, Facebook, Twitter, Github, etc.)
- [ ] Add more features (Forgot password, Reset password, etc.)
- [ ] Customizable routers.
