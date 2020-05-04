"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class AuthController {
    loginAction(req, namespace = 'user.ops', redirect) {
        const user = req.user;
        if (user && user.namespace !== namespace) {
            req.logout();
        }
        return { data: { namespace, user: req.user, redirect } };
    }
    loginCheckAction(data, request) {
        const response = { success: true };
        if (!request.user) {
            response.success = false;
        }
        if (request.get('accept') === 'application/json') {
            return response;
        }
        else {
            return request.res.redirect('/auth/login');
        }
    }
    logoutAction(req) {
        if (req.isAuthenticated()) {
            req.logOut();
        }
        if (req.get('accept') === 'application/json') {
            return { ok: true };
        }
        else {
            req.res.redirect('/auth/login');
        }
    }
}
exports.AuthController = AuthController;
//# sourceMappingURL=controller.js.map