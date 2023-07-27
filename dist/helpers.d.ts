import { AuthModuleOptions, PassportVerifyFunction, PassportVerifyFunctionWithRequest } from './types';
export declare const passportVerifier: PassportVerifyFunction;
export declare const passportVerifierWithRequest: PassportVerifyFunctionWithRequest;
export declare const getStrategyError: (err: any, user: any, info: any, status: any) => Error;
export declare const encrypt: (input: string, key: string) => string;
export declare const decrypt: (encryptedText: string, key: string) => string;
export declare const getTokenExpiresIn: (token: string) => number;
export declare const getOptions: <Entity, JwtPayload>(opts: AuthModuleOptions<Entity, JwtPayload, import("typeorm").ObjectLiteral>) => AuthModuleOptions<Entity, JwtPayload, import("typeorm").ObjectLiteral>;
