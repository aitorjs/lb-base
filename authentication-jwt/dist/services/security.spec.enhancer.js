"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecuritySpecEnhancer = exports.SECURITY_SCHEME_SPEC = exports.OPERATION_SECURITY_SPEC = void 0;
const tslib_1 = require("tslib");
const core_1 = require("@loopback/core");
// Copyright IBM Corp. 2019. All Rights Reserved.
// Node module: @loopback/authentication-jwt"
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT
const rest_1 = require("@loopback/rest");
const debug_1 = (0, tslib_1.__importDefault)(require("debug"));
const debug = (0, debug_1.default)('loopback:jwt-extension:spec-enhancer');
exports.OPERATION_SECURITY_SPEC = [
    {
        // secure all endpoints with 'jwt'
        jwt: [],
    },
];
exports.SECURITY_SCHEME_SPEC = {
    jwt: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
    },
};
/**
 * A spec enhancer to add bearer token OpenAPI security entry to
 * `spec.component.securitySchemes`
 */
let SecuritySpecEnhancer = class SecuritySpecEnhancer {
    constructor() {
        this.name = 'bearerAuth';
    }
    modifySpec(spec) {
        console.log("modified authentication-jwt");
        /* const patchSpec = {
          components: {
            securitySchemes: SECURITY_SCHEME_SPEC,
          },
          security: OPERATION_SECURITY_SPEC,
        };
        const mergedSpec = mergeOpenAPISpec(spec, patchSpec);
        debug(`security spec extension, merged spec: ${inspect(mergedSpec)}`);
        return mergedSpec; */
        return spec;
    }
};
SecuritySpecEnhancer = (0, tslib_1.__decorate)([
    (0, core_1.injectable)(rest_1.asSpecEnhancer)
], SecuritySpecEnhancer);
exports.SecuritySpecEnhancer = SecuritySpecEnhancer;
//# sourceMappingURL=security.spec.enhancer.js.map