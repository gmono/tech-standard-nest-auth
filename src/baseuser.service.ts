import * as argon2 from 'argon2';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { decrypt, encrypt } from './helpers';
import {
  DeepPartial,
  FindOptionsWhere,
  ObjectLiteral,
  Repository,
} from 'typeorm';
import {
  AuthModuleConfig,
  AUTH_CONFIG,
  JwtPayload,
  PassportCallbackData,
  UserAuthServiceType,
} from './types';

// Setting for auth module, all the following properties and methods are optional
@Injectable()
export class BaseUserService<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayloadSub extends ObjectLiteral = ObjectLiteral,
  RegisterDTO extends ObjectLiteral = ObjectLiteral,
> implements UserAuthServiceType<Entity, JwtPayloadSub, RegisterDTO>
{
  constructor(
    public userRepository: Repository<Entity>,
    @Inject(AUTH_CONFIG) public options: AuthModuleConfig,
  ) { }

  // Custom user ID field, default is 'id'
  public IDField = 'id';

  // Custom DB fields for checking local user login
  public dbUsernameFields: string[] = ['username', 'email'];
  public dbPasswordField = 'password';

  // Custom request body fields for local login
  public requestUsernameField = 'username';
  public requestPasswordField = 'password';

  // Custom user register method
  async register(data: RegisterDTO): Promise<{ user: Entity, token: string }> {
    const userData = data as unknown as Entity;
    const passwordField = this.dbPasswordField as keyof Entity;
    userData[passwordField] = (await this.hashPassword(
      userData[passwordField] as string,
    )) as Entity[keyof Entity];
    const user = this.userRepository.create(
      userData as unknown as DeepPartial<Entity>,
    );
    const savedUser = await this.userRepository.save(user);
    delete savedUser[passwordField];

    // token should be url encoded before sending to client
    const token = encrypt(
      JSON.stringify({
        [this.IDField]: savedUser[this.IDField],
        createdAt: new Date().getTime(),
      }),
      this.options.recovery.tokenSecret,
    );

    return { user: savedUser, token };
  }

  // Custom user login method
  async login(username: string, password: string): Promise<Entity> {
    const user = await this.userRepository.findOne({
      where: this.dbUsernameFields.map((field) => ({
        [field]: username,
      })) as FindOptionsWhere<Entity>[],
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const validPassword = await this.verifyPassword(
      password,
      user[this.dbPasswordField] as string,
    );

    if (!user || !validPassword) {
      throw new UnauthorizedException();
    }

    return user;
  }

  // Custom user forgot password method
  async generateForgotPasswordToken(
    identityValue: string,
  ): Promise<{ user: Entity; token: string }> {
    const user = await this.userRepository.findOne({
      where: this.dbUsernameFields.map((field) => ({
        [field]: identityValue,
      })) as FindOptionsWhere<Entity>[],
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    // token should be url encoded before sending to client
    const token = encrypt(
      JSON.stringify({
        [this.IDField]: user[this.IDField],
        createdAt: new Date().getTime(),
      }),
      this.options.recovery.tokenSecret,
    );

    return { user, token };
  }

  async verifyToken(
    token: string,
    ignoreExpired?: boolean,
  ): Promise<{ user: Entity; createdAt: number }> {
    const decrypted = decrypt(token, this.options.recovery.tokenSecret);
    const result = JSON.parse(decrypted);
    const user = await this.userRepository.findOneBy({
      [this.IDField]: result[this.IDField],
    } as FindOptionsWhere<Entity>);

    if (!user) {
      throw new UnauthorizedException();
    }

    if (
      !ignoreExpired &&
      new Date().getTime() - result.createdAt >
      this.options.recovery.tokenExpiresIn * 1000
    ) {
      throw new UnauthorizedException();
    }

    return { user, createdAt: result.createdAt };
  }

  async changePassword(user: Entity, oldPassword: string, newPassword: string): Promise<boolean> {
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!oldPassword || !newPassword) {
      throw new UnauthorizedException('Password cannot be empty');
    }


    const validPassword = await this.verifyPassword(
      oldPassword,
      user[this.dbPasswordField] as string,
    );

    if (!validPassword) {
      throw new UnauthorizedException('Old password is incorrect');
    }

    const passwordField = this.dbPasswordField as keyof Entity;
    user[passwordField] = await this.hashPassword(newPassword) as Entity[keyof Entity];
    await this.userRepository.save(user);

    return false
  }

  async hashPassword(input: string): Promise<string> {
    return argon2.hash(input, {
      secret: Buffer.from(this.options.passwordHashSecret),
    });
  }

  async verifyPassword(
    input: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return argon2.verify(hashedPassword, input, {
      secret: Buffer.from(this.options.passwordHashSecret),
    });
  }

  // Custom Jwt access token payload, default is { id }
  async createJwtAccessTokenPayload(
    user: Entity,
  ): Promise<JwtPayload<JwtPayloadSub>> {
    if (!user[this.IDField]) {
      throw new Error(
        `${this.IDField} is not defined in user object: ${JSON.stringify(
          user,
        )}`,
      );
    }

    const payload = {
      sub: {
        [this.IDField]: user[this.IDField],
      },
    };

    return payload as JwtPayload;
  }

  // Custom Jwt refresh token payload, default is { id }
  async createJwtRefreshTokenPayload(
    user: Entity,
  ): Promise<JwtPayload<Partial<JwtPayloadSub>>> {
    return this.createJwtAccessTokenPayload(user);
  }

  // Custom Jwt validator, default is { ...user }
  async jwtValidator(payload: JwtPayloadSub) {
    if (!payload.sub[this.IDField]) {
      throw new Error('Invalid JWT payload');
    }

    const user = await this.userRepository.findOneBy({
      [this.IDField]: payload.sub[this.IDField],
    } as FindOptionsWhere<Entity>);

    if (!user) {
      throw new UnauthorizedException();
    }

    delete user[this.dbPasswordField];
    return user;
  }

  async onBeforePassportAuthenticateResponse(
    provider: string,
    data: PassportCallbackData,
  ) {
    throw new Error('Method not implemented.');
  }

  async onBeforeRegisterResponse(body: RegisterDTO, token: string, user: Entity) {
    return {
      // body,
      // token,
      user,
    };
  }

  async onBeforeLoginResponse(
    user: Entity,
    refreshToken: string,
    accessToken: string,
    refreshTokenExpiresAt: number,
    accessTokenExpiresAt: number,
  ) {
    return {
      // user,
      // refreshToken,
      // accessToken,
      refresh_token: refreshToken,
      access_token: accessToken,
      token_type: 'Bearer',
      expires_at: accessTokenExpiresAt,
    };
  }

  async onBeforeForgotPasswordResponse(user: Entity, token: string) {
    return {
      ok: true,
      type: 'forgotPassword',
    };
  }

  async onBeforeVerifyForgotPasswordResponse(
    user: Entity,
    token: string,
    createdAt: number,
  ) {
    return {
      ok: true,
      type: 'verifyForgotPassword',
    };
  }

  async onBeforeVerifyRegisterResponse(
    user: Entity,
    token: string,
    createdAt: number,
  ) {
    return {
      ok: true,
      type: 'verifyRegister',
    };
  }

  async onBeforeChangePasswordResponse(user: Entity, oldPassword: string, newPassword: string, success: boolean): Promise<any> {
    return {
      ok: true,
      type: 'changePassword',
    };
  }

  async onBeforeLogoutResponse(accessToken: string) {
    return null;
  }

  async onBeforeRefreshTokenResponse(
    user: Entity,
    refreshToken: string,
    accessToken: string,
    refreshTokenExpiresAt: number,
    accessTokenExpiresAt: number,
  ) {
    return {
      refresh_token: refreshToken,
      access_token: accessToken,
      token_type: 'Bearer',
      expires_at: accessTokenExpiresAt,
    };
  }
}
