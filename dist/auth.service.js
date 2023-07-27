"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const passport = require("passport");
const jwt_1 = require("@nestjs/jwt");
const passport_jwt_1 = require("passport-jwt");
const common_1 = require("@nestjs/common");
const typeorm_1 = require("typeorm");
const helpers_1 = require("./helpers");
const baseuser_service_1 = require("./baseuser.service");
const types_1 = require("./types");
let AuthService = class AuthService {
    constructor(jwtService, dataSource, userEntity, userService, opts) {
        this.jwtService = jwtService;
        this.dataSource = dataSource;
        this.userEntity = userEntity;
        this.userService = userService;
        this.opts = opts;
        this.userRepository = this.userEntity
            ? this.dataSource.getRepository(this.userEntity)
            : null;
        if (this.userService.constructor.name === 'UseDefaultUserService') {
            this.userService = new baseuser_service_1.BaseUserService(this.userRepository, opts);
        }
        if (opts.passportStrategies && opts.passportStrategies.length) {
            if (this.userService.onBeforePassportAuthenticateResponse ===
                baseuser_service_1.BaseUserService.prototype.onBeforePassportAuthenticateResponse) {
                throw new Error('onBeforePassportAuthenticateResponse must be implemented in your custom user service when using passport strategies');
            }
            this.passport = new passport.Passport();
            for (const strategy of opts.passportStrategies) {
                this.passport.use(strategy);
                this.passport.serializeUser((user, cb) => process.nextTick(() => cb(null, user)));
                this.passport.deserializeUser((user, cb) => process.nextTick(() => cb(null, user)));
            }
        }
    }
    getUserFromAccessTokenOrVerifyToken(accessToken, token, ignoreExpiration) {
        return __awaiter(this, void 0, void 0, function* () {
            let user;
            if (accessToken) {
                let payload;
                try {
                    payload = this.jwtService.verify(accessToken, Object.assign(Object.assign({}, (this.opts.jwt.refresh || {})), { ignoreExpiration }));
                }
                catch (e) {
                    throw new common_1.UnauthorizedException();
                }
                user = yield this.userService.jwtValidator(payload);
            }
            if (token) {
                const { user: userFromToken } = yield this.userService.verifyToken(token, ignoreExpiration);
                user = userFromToken;
            }
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            return user;
        });
    }
    passportAuthenticate(providerName, req, res) {
        this.passport.authenticate(providerName)(req, res);
    }
    passportAuthenticateCallback(providerName, req) {
        return __awaiter(this, void 0, void 0, function* () {
            return new Promise((resolve) => {
                this.passport.authenticate(providerName, { session: false }, (rawErr, user, info, status) => {
                    resolve({
                        rawErr,
                        user,
                        info,
                        status,
                        err: (0, helpers_1.getStrategyError)(rawErr, user, info, status),
                    });
                })(req);
            });
        });
    }
    jwtExtractor() {
        return this.opts.jwt.jwtFromRequest
            ? this.opts.jwt.jwtFromRequest()
            : passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken();
    }
    getLoginTokens(user) {
        return __awaiter(this, void 0, void 0, function* () {
            const [refreshTokenPayload, accessTokenPayload] = yield Promise.all([
                this.userService.createJwtRefreshTokenPayload(user),
                this.userService.createJwtAccessTokenPayload(user),
            ]);
            const [refreshToken, accessToken] = yield Promise.all([
                this.jwtService.signAsync(refreshTokenPayload, Object.assign({}, (this.opts.jwt.refresh || {}))),
                this.jwtService.signAsync(accessTokenPayload),
            ]);
            return {
                refreshToken,
                accessToken,
                refreshTokenExpiresAt: (0, helpers_1.getTokenExpiresIn)(refreshToken),
                accessTokenExpiresAt: (0, helpers_1.getTokenExpiresIn)(accessToken),
            };
        });
    }
    refreshToken(refresh_token) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!refresh_token) {
                throw new common_1.UnauthorizedException('Refresh token is required');
            }
            let payload;
            try {
                payload = this.jwtService.verify(refresh_token, Object.assign(Object.assign({}, (this.opts.jwt.refresh || {})), { ignoreExpiration: false }));
            }
            catch (e) {
                throw new common_1.UnauthorizedException();
            }
            const user = yield this.userService.jwtValidator(payload);
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            const tokenPromises = [
                this.jwtService.signAsync(yield this.userService.createJwtAccessTokenPayload(user)),
            ];
            if (this.opts.enableRefreshTokenRotation) {
                tokenPromises.push(this.jwtService.signAsync(yield this.userService.createJwtRefreshTokenPayload(user), Object.assign({}, (this.opts.jwt.refresh || {}))));
            }
            const [accessToken, refreshToken] = yield Promise.all(tokenPromises);
            return {
                user,
                accessToken,
                refreshToken: refreshToken || refresh_token,
                refreshTokenExpiresAt: (0, helpers_1.getTokenExpiresIn)(refreshToken || refresh_token),
                accessTokenExpiresAt: (0, helpers_1.getTokenExpiresIn)(accessToken)
            };
        });
    }
};
AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(2, (0, common_1.Inject)(types_1.USER_ENTITY)),
    __param(3, (0, common_1.Inject)(types_1.USER_SERVICE)),
    __param(4, (0, common_1.Inject)(types_1.AUTH_CONFIG)),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        typeorm_1.DataSource, Object, types_1.UserAuthServiceType, Object])
], AuthService);
exports.AuthService = AuthService;
