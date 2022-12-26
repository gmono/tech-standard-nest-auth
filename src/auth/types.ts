import { DynamicModule, ForwardReference, Type } from '@nestjs/common';
import { EntityTarget, ObjectLiteral } from 'typeorm';

export type NestModule = DynamicModule | Type<any> | Promise<DynamicModule> | ForwardReference<any>;

export interface JwtOptions {
  accessTokenSecretOrKey: string;
  accessTokenExpiresIn: string;
  refreshTokenSecretOrKey?: string;
  refreshTokenExpiresIn?: string;
}

export interface AuthModuleExtraOptions {
  jwt?: JwtOptions,
  enableRefreshTokenRotation?: boolean,
  passwordHashSecret?: string,
}

export interface AuthModuleOptions<
  Entity extends ObjectLiteral = ObjectLiteral,
  JwtPayload extends ObjectLiteral = ObjectLiteral,
  RegisterDTO extends ObjectLiteral = ObjectLiteral,
> {
  typeormUserEntity?: EntityTarget<Entity>,
  userService?: typeof UserAuthServiceType<Entity, JwtPayload, RegisterDTO>,
  options?: AuthModuleExtraOptions,
  imports?: NestModule[],
}

export interface JwtPayload<T = any> {
  sub: T;
}

export abstract class UserAuthServiceType<Entity, JwtPayloadSub, RegisterDTO> {
  public IDField = 'id';
  public dbUsernameFields?: string[];
  public dbPasswordField?: string;
  public requestUsernameField?: string;
  public requestPasswordField?: string;

  constructor(...args: any[]) {
    return this;
  };

  abstract register(data: RegisterDTO): Promise<Entity>;
  abstract login(username: string, password: string): Promise<Entity>;
  abstract createJwtAccessTokenPayload(user: Entity): Promise<JwtPayload<JwtPayloadSub>>;
  abstract createJwtRefreshTokenPayload(user: Entity): Promise<JwtPayload<Partial<JwtPayloadSub>>>;
  abstract jwtValidator(payload: JwtPayloadSub): Promise<Entity>;
  abstract hashPassword(input: string): Promise<string>;
  abstract verifyPassword(input: string, hashedPassword: string): Promise<boolean>;

  abstract onBeforeRegisterResponse(body: RegisterDTO, user: Entity): any;
  abstract onBeforeLoginResponse(user: Entity, refreshToken: string, accessToken: string): any;
  abstract onBeforeRefreshTokenResponse(
    oldPayload: JwtPayloadSub,
    user: Entity,
    refreshToken: string,
    accessToken: string,
  ): any;
}

// export class AuthServiceClassType<Entity, JwtPayload> {
//   public identityFields?: string[];
//   public passwordField?: string;

//   constructor(...args: any[]) {
//     return this;
//   }

//   localStrategyOptions(): IStrategyOptions {
//     throw new Error('Method not implemented.');
//   }

//   async checkLogin(username: string, password: string): Promise<Entity> {
//     throw new Error('Method not implemented.');
//   };

//   async register(data: Entity): Promise<Entity> {
//     throw new Error('Method not implemented.');
//   };

//   async createJwtSignerPayload(user: Entity): Promise<JwtPayload> {
//     throw new Error('Method not implemented.');
//   }

//   async jwtValidator(payload: JwtPayload): Promise<Entity> {
//     throw new Error('Method not implemented.');
//   }
// }
