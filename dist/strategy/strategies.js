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
exports.JwtRefreshTokenStrategy = exports.JwtAccessTokenStrategy = exports.LocalStrategy = void 0;
const passport_1 = require("@nestjs/passport");
const passport_jwt_1 = require("passport-jwt");
const passport_local_1 = require("passport-local");
const common_1 = require("@nestjs/common");
const auth_service_1 = require("../auth.service");
const types_1 = require("../types");
let LocalStrategy = class LocalStrategy extends (0, passport_1.PassportStrategy)(passport_local_1.Strategy) {
    constructor(authService) {
        super({
            usernameField: authService.userService.requestUsernameField || 'username',
            passwordField: authService.userService.requestPasswordField || 'password',
        });
        this.authService = authService;
    }
    validate(username, password) {
        return __awaiter(this, void 0, void 0, function* () {
            const user = yield this.authService.userService.login(username, password);
            if (!user) {
                throw new common_1.UnauthorizedException();
            }
            return user;
        });
    }
};
LocalStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], LocalStrategy);
exports.LocalStrategy = LocalStrategy;
let JwtAccessTokenStrategy = class JwtAccessTokenStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-access-token') {
    constructor(authService, opts) {
        const secretOrKey = opts.jwt.secret || opts.jwt.privateKey || opts.jwt.secretOrPrivateKey;
        super({
            secretOrKey,
            ignoreExpiration: false,
            passReqToCallback: false,
            jwtFromRequest: authService.jwtExtractor(),
        });
        this.authService = authService;
        this.opts = opts;
    }
    validate(payload) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.authService.userService.jwtValidator(payload);
        });
    }
};
JwtAccessTokenStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(types_1.AUTH_CONFIG)),
    __metadata("design:paramtypes", [auth_service_1.AuthService, Object])
], JwtAccessTokenStrategy);
exports.JwtAccessTokenStrategy = JwtAccessTokenStrategy;
let JwtRefreshTokenStrategy = class JwtRefreshTokenStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy, 'jwt-refresh-token') {
    constructor(authService, opts) {
        const refreshOpts = opts.jwt.refresh || {};
        const secretOrKey = refreshOpts.secret ||
            refreshOpts.privateKey ||
            opts.jwt.secret ||
            opts.jwt.privateKey ||
            opts.jwt.secretOrPrivateKey;
        super({
            secretOrKey,
            ignoreExpiration: false,
            passReqToCallback: true,
            jwtFromRequest: authService.jwtExtractor(),
        });
        this.authService = authService;
        this.opts = opts;
    }
    validate(req, payload) {
        const refreshToken = this.authService.jwtExtractor()(req);
        return Object.assign(Object.assign({}, payload), { refreshToken });
    }
};
JwtRefreshTokenStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(types_1.AUTH_CONFIG)),
    __metadata("design:paramtypes", [auth_service_1.AuthService, Object])
], JwtRefreshTokenStrategy);
exports.JwtRefreshTokenStrategy = JwtRefreshTokenStrategy;
