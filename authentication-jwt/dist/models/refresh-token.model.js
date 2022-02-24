"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RefreshToken = void 0;
const tslib_1 = require("tslib");
const repository_1 = require("@loopback/repository");
const _1 = require(".");
let RefreshToken = class RefreshToken extends repository_1.Entity {
    constructor(data) {
        super(data);
    }
};
(0, tslib_1.__decorate)([
    (0, repository_1.property)({
        type: 'number',
        id: 1,
        generated: true,
    }),
    (0, tslib_1.__metadata)("design:type", Number)
], RefreshToken.prototype, "id", void 0);
(0, tslib_1.__decorate)([
    (0, repository_1.belongsTo)(() => _1.User),
    (0, tslib_1.__metadata)("design:type", String)
], RefreshToken.prototype, "userId", void 0);
(0, tslib_1.__decorate)([
    (0, repository_1.property)({
        type: 'string',
        required: true,
    }),
    (0, tslib_1.__metadata)("design:type", String)
], RefreshToken.prototype, "refreshToken", void 0);
RefreshToken = (0, tslib_1.__decorate)([
    (0, repository_1.model)({ settings: { strict: false } }),
    (0, tslib_1.__metadata)("design:paramtypes", [Object])
], RefreshToken);
exports.RefreshToken = RefreshToken;
//# sourceMappingURL=refresh-token.model.js.map