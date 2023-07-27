import { BaseUserService, AuthModuleConfig, PassportCallbackData } from '../';
import { Repository } from 'typeorm';
import { UserEntity } from './user.entity';
import { JwtPayload, UserRegisterDto } from './types';
export declare class CustomUserService extends BaseUserService<UserEntity, JwtPayload, UserRegisterDto> {
    config: AuthModuleConfig;
    constructor(userRepository: Repository<UserEntity>, config: AuthModuleConfig);
    onBeforePassportAuthenticateResponse(provider: string, data: PassportCallbackData): Promise<any>;
}
