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
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const guards_1 = require("./strategy/guards");
const auth_service_1 = require("./auth.service");
let AuthController = class AuthController {
    constructor(authService) {
        this.authService = authService;
    }
    register(body) {
        return __awaiter(this, void 0, void 0, function* () {
            const { user, token } = yield this.authService.userService.register(body);
            return yield this.authService.userService.onBeforeRegisterResponse(body, token, user);
        });
    }
    confirm(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const token = req.query.token;
            const { user, createdAt } = yield this.authService.userService.verifyToken(token);
            return yield this.authService.userService.onBeforeVerifyRegisterResponse(user, token, createdAt);
        });
    }
    login(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const { refreshToken, accessToken, refreshTokenExpiresAt, accessTokenExpiresAt, } = yield this.authService.getLoginTokens(req.user);
            return yield this.authService.userService.onBeforeLoginResponse(req.user, refreshToken, accessToken, refreshTokenExpiresAt, accessTokenExpiresAt);
        });
    }
    forgotPassword(body) {
        return __awaiter(this, void 0, void 0, function* () {
            const { user, token } = yield this.authService.userService.generateForgotPasswordToken(body === null || body === void 0 ? void 0 : body.identity);
            return yield this.authService.userService.onBeforeForgotPasswordResponse(user, token);
        });
    }
    verifyForgotPaswordToken(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const token = req.query.token;
            const { user, createdAt } = yield this.authService.userService.verifyToken(token);
            return yield this.authService.userService.onBeforeVerifyForgotPasswordResponse(user, token, createdAt);
        });
    }
    changePassword(body, req) {
        return __awaiter(this, void 0, void 0, function* () {
            const { old_password, password, token } = body;
            const accessToken = this.authService.jwtExtractor()(req);
            const user = yield this.authService.getUserFromAccessTokenOrVerifyToken(accessToken, token);
            const isForgot = !!token;
            const result = yield this.authService.userService.changePassword(user, password, isForgot, old_password);
            return yield this.authService.userService.onBeforeChangePasswordResponse(user, old_password, password, result);
        });
    }
    logout(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const accessToken = this.authService.jwtExtractor()(req);
            return yield this.authService.userService.onBeforeLogoutResponse(accessToken);
        });
    }
    refreshTokens(body, req) {
        return __awaiter(this, void 0, void 0, function* () {
            const { refresh_token } = body;
            const { user, accessToken, refreshToken, refreshTokenExpiresAt, accessTokenExpiresAt } = yield this.authService.refreshToken(refresh_token);
            return yield this.authService.userService.onBeforeRefreshTokenResponse(user, refreshToken, accessToken, refreshTokenExpiresAt, accessTokenExpiresAt);
        });
    }
    passportAuthenticate(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.authService.passportAuthenticate(req.params.provider, req, res);
        });
    }
    passportAuthenticateCallback(req) {
        return __awaiter(this, void 0, void 0, function* () {
            const result = yield this.authService.passportAuthenticateCallback(req.params.provider, req);
            return yield this.authService.userService.onBeforePassportAuthenticateResponse(req.params.provider, result);
        });
    }
    me(req) {
        return req.user;
    }
};
__decorate([
    (0, common_1.Post)('/register'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Get)('/confirm'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "confirm", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.UseGuards)(guards_1.LocalAuthGuard),
    (0, common_1.Post)('/login'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('/forgot-password'),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "forgotPassword", null);
__decorate([
    (0, common_1.Get)('/forgot-password'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "verifyForgotPaswordToken", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('/change-password'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "changePassword", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.UseGuards)(guards_1.AccessTokenAuthGuard),
    (0, common_1.Post)('logout'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.HttpCode)(200),
    (0, common_1.Post)('refresh'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refreshTokens", null);
__decorate([
    (0, common_1.Get)('/social/sign-in/:provider'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "passportAuthenticate", null);
__decorate([
    (0, common_1.Get)('/social/sign-in/:provider/callback'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "passportAuthenticateCallback", null);
__decorate([
    (0, common_1.UseGuards)(guards_1.AccessTokenAuthGuard),
    (0, common_1.Get)('/me'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "me", null);
AuthController = __decorate([
    (0, common_1.Controller)(''),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], AuthController);
exports.AuthController = AuthController;
