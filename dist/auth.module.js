"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthModule = void 0;
const jwt_1 = require("@nestjs/jwt");
const typeorm_1 = require("@nestjs/typeorm");
const passport_1 = require("@nestjs/passport");
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
const auth_controller_1 = require("./auth.controller");
const strategies_1 = require("./strategy/strategies");
const types_1 = require("./types");
const helpers_1 = require("./helpers");
let AuthModule = AuthModule_1 = class AuthModule {
    static register(opts) {
        if (opts.authKey.length < 32) {
            throw new Error('authKey must be at least 32 characters long');
        }
        opts = (0, helpers_1.getOptions)(opts);
        const { typeormUserEntity, userService, config, imports } = opts;
        const UserServiceClass = userService || class UseDefaultUserService {
        };
        return {
            module: AuthModule_1,
            imports: [
                passport_1.PassportModule,
                jwt_1.JwtModule.register(config.jwt),
                typeormUserEntity
                    ? typeorm_1.TypeOrmModule.forFeature([typeormUserEntity])
                    : null,
                ...(imports || []),
            ].filter((i) => !!i),
            providers: [
                {
                    provide: types_1.USER_ENTITY,
                    useValue: typeormUserEntity || null,
                },
                {
                    provide: types_1.USER_SERVICE,
                    useClass: UserServiceClass,
                },
                {
                    provide: types_1.AUTH_CONFIG,
                    useValue: config,
                },
                UserServiceClass,
                (auth_service_1.AuthService),
                (strategies_1.JwtAccessTokenStrategy),
                (strategies_1.JwtRefreshTokenStrategy),
                (strategies_1.LocalStrategy),
            ],
            exports: [auth_service_1.AuthService, types_1.USER_SERVICE, types_1.AUTH_CONFIG],
            controllers: opts.disableRouter ? [] : [auth_controller_1.AuthController],
        };
    }
};
AuthModule = AuthModule_1 = __decorate([
    (0, common_1.Module)({}),
    (0, common_1.Global)()
], AuthModule);
exports.AuthModule = AuthModule;
