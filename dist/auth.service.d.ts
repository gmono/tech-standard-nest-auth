import passport = require('passport');
import { JwtService } from '@nestjs/jwt';
import { Request, Response } from 'express';
import { JwtFromRequestFunction } from 'passport-jwt';
import { DataSource, EntityTarget, ObjectLiteral } from 'typeorm';
import { AuthModuleConfig, UserAuthServiceType } from './types';
export declare class AuthService<Entity extends ObjectLiteral = ObjectLiteral, JwtPayload extends ObjectLiteral = ObjectLiteral, RegisterDTO extends ObjectLiteral = ObjectLiteral> {
    private jwtService;
    private dataSource;
    private userEntity;
    userService: UserAuthServiceType<Entity, JwtPayload, RegisterDTO>;
    private opts;
    private userRepository;
    passport: passport.Authenticator;
    constructor(jwtService: JwtService, dataSource: DataSource, userEntity: EntityTarget<Entity>, userService: UserAuthServiceType<Entity, JwtPayload, RegisterDTO>, opts: AuthModuleConfig);
    getUserFromAccessTokenOrVerifyToken(accessToken?: string, token?: string, ignoreExpiration?: boolean): Promise<Entity>;
    passportAuthenticate(providerName: string, req: Request, res: Response): void;
    passportAuthenticateCallback(providerName: string, req: Request): Promise<{
        err: Error;
        rawErr: any;
        user: any;
        info: any;
        status: any;
    }>;
    jwtExtractor(): JwtFromRequestFunction;
    getLoginTokens(user: Entity): Promise<{
        refreshToken: string;
        accessToken: string;
        refreshTokenExpiresAt: number;
        accessTokenExpiresAt: number;
    }>;
    refreshToken(refresh_token: string): Promise<{
        user: Entity;
        accessToken: string;
        refreshToken: string;
        refreshTokenExpiresAt: number;
        accessTokenExpiresAt: number;
    }>;
}
