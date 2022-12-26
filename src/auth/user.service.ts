import * as argon2 from 'argon2';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthModuleExtraOptions, JwtPayload, UserAuthServiceType } from 'src/auth/types';
import { DeepPartial, FindOptionsWhere, ObjectLiteral, Repository } from 'typeorm';
import { EXTRA_OPTIONS } from './symbols';

// Setting for auth module, all the following properties and methods are optional
@Injectable()
export class BaseUserService<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayloadSub extends ObjectLiteral = ObjectLiteral,
  RegisterDTO extends ObjectLiteral = ObjectLiteral,
> implements UserAuthServiceType<Entity, JwtPayloadSub, RegisterDTO> {
  constructor(
    public userRepository: Repository<Entity>,
    @Inject(EXTRA_OPTIONS) public options: AuthModuleExtraOptions,
  ) { }

  // Custom user ID field, default is 'id'
  public IDField: string = 'id';

  // Custom DB fields for checking local user login
  public dbUsernameFields: string[] = ['username', 'email'];
  public dbPasswordField: string = 'password';

  // Custom request body fields for local login
  public requestUsernameField: string = 'username';
  public requestPasswordField: string = 'password';

  async hashPassword(input: string): Promise<string> {
    return argon2.hash(input, {
      secret: Buffer.from(this.options.passwordHashSecret),
    });
  }

  async verifyPassword(input: string, hashedPassword: string): Promise<boolean> {
    return argon2.verify(hashedPassword, input, {
      secret: Buffer.from(this.options.passwordHashSecret),
    });
  }

  async onBeforeRegisterResponse(body: RegisterDTO, user: Entity) {
    return {
      // body,
      user,
    };
  }

  async onBeforeLoginResponse(user: Entity, refreshToken: string, accessToken: string) {
    return {
      // user,
      refreshToken,
      accessToken,
    };
  }

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
}
