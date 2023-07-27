import { Request } from 'express';
import { ObjectLiteral } from 'typeorm';
import { Strategy as PassportJwtStrategy } from 'passport-jwt';
import { Strategy as PassportLocalStrategy } from 'passport-local';
import { AuthService } from '../auth.service';
import { AuthModuleConfig } from '../types';
declare const LocalStrategy_base: new (...args: any[]) => PassportLocalStrategy;
export declare class LocalStrategy<Entity extends ObjectLiteral> extends LocalStrategy_base {
    private authService;
    constructor(authService: AuthService<Entity>);
    validate(username: string, password: string): Promise<Entity>;
}
declare const JwtAccessTokenStrategy_base: new (...args: any[]) => PassportJwtStrategy;
export declare class JwtAccessTokenStrategy<Entity extends ObjectLiteral, JwtPayload extends ObjectLiteral> extends JwtAccessTokenStrategy_base {
    private authService;
    opts: AuthModuleConfig;
    constructor(authService: AuthService, opts: AuthModuleConfig);
    validate(payload: JwtPayload): Promise<ObjectLiteral>;
}
declare const JwtRefreshTokenStrategy_base: new (...args: any[]) => PassportJwtStrategy;
export declare class JwtRefreshTokenStrategy<Entity extends ObjectLiteral, JwtPayload extends ObjectLiteral> extends JwtRefreshTokenStrategy_base {
    private authService;
    opts: AuthModuleConfig;
    constructor(authService: AuthService, opts: AuthModuleConfig);
    validate(req: Request, payload: JwtPayload): JwtPayload & {
        refreshToken: string;
    };
}
export {};
