import { ObjectLiteral, Repository } from 'typeorm';
import { AuthModuleConfig, JwtPayload, PassportCallbackData, UserAuthServiceType } from './types';
export declare class BaseUserService<Entity extends ObjectLiteral = ObjectLiteral, JwtPayloadSub extends ObjectLiteral = ObjectLiteral, RegisterDTO extends ObjectLiteral = ObjectLiteral> implements UserAuthServiceType<Entity, JwtPayloadSub, RegisterDTO> {
    userRepository: Repository<Entity>;
    options: AuthModuleConfig;
    constructor(userRepository: Repository<Entity>, options: AuthModuleConfig);
    IDField: string;
    dbIdentityFields: string[];
    dbPasswordField: string;
    requestUsernameField: string;
    requestPasswordField: string;
    register(data: RegisterDTO): Promise<{
        user: Entity;
        token: string;
    }>;
    login(username: string, password: string): Promise<Entity>;
    generateForgotPasswordToken(identityValue: string): Promise<{
        user: Entity;
        token: string;
    }>;
    verifyToken(token: string, ignoreExpired?: boolean): Promise<{
        user: Entity;
        createdAt: number;
    }>;
    changePassword(user: Entity, newPassword: string, isForgot?: boolean, oldPassword?: string): Promise<boolean>;
    hashPassword(input: string): Promise<string>;
    verifyPassword(input: string, hashedPassword: string): Promise<boolean>;
    createJwtAccessTokenPayload(user: Entity): Promise<JwtPayload<JwtPayloadSub>>;
    createJwtRefreshTokenPayload(user: Entity): Promise<JwtPayload<Partial<JwtPayloadSub>>>;
    jwtValidator(payload: JwtPayloadSub): Promise<Entity>;
    onBeforePassportAuthenticateResponse(provider: string, data: PassportCallbackData): Promise<void>;
    onBeforeRegisterResponse(body: RegisterDTO, token: string, user: Entity): Promise<{
        user: Entity;
    }>;
    onBeforeLoginResponse(user: Entity, refreshToken: string, accessToken: string, refreshTokenExpiresAt: number, accessTokenExpiresAt: number): Promise<{
        refresh_token: string;
        access_token: string;
        token_type: string;
        expires_at: number;
    }>;
    onBeforeForgotPasswordResponse(user: Entity, token: string): Promise<{
        ok: boolean;
        type: string;
    }>;
    onBeforeVerifyForgotPasswordResponse(user: Entity, token: string, createdAt: number): Promise<{
        ok: boolean;
        type: string;
    }>;
    onBeforeVerifyRegisterResponse(user: Entity, token: string, createdAt: number): Promise<{
        ok: boolean;
        type: string;
    }>;
    onBeforeChangePasswordResponse(user: Entity, oldPassword: string, newPassword: string, success: boolean): Promise<any>;
    onBeforeLogoutResponse(accessToken: string): Promise<any>;
    onBeforeRefreshTokenResponse(user: Entity, refreshToken: string, accessToken: string, refreshTokenExpiresAt: number, accessTokenExpiresAt: number): Promise<{
        token_type: string;
        refresh_token: string;
        access_token: string;
        expires_at: number;
    }>;
}
