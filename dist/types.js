"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserAuthServiceType = exports.AUTH_CONFIG = exports.USER_SERVICE = exports.USER_ENTITY = void 0;
exports.USER_ENTITY = Symbol('USER_ENTITY');
exports.USER_SERVICE = Symbol('USER_SERVICE');
exports.AUTH_CONFIG = Symbol('AUTH_CONFIG');
class UserAuthServiceType {
    constructor(...args) {
        this.IDField = 'id';
        return this;
    }
}
exports.UserAuthServiceType = UserAuthServiceType;
