import { DynamicModule } from '@nestjs/common';
import { AuthModuleOptions } from './types';
import { ObjectLiteral } from 'typeorm';
export declare class AuthModule {
    static register<Entity extends ObjectLiteral = ObjectLiteral, JwtPayload extends ObjectLiteral = ObjectLiteral, RegisterDTO extends ObjectLiteral = ObjectLiteral>(opts: AuthModuleOptions<Entity, JwtPayload, RegisterDTO>): DynamicModule;
}
