import { createMiddleware } from 'hono/factory';
import { verify } from 'hono/jwt';

import type { Bindings, Variables } from '../types/types';

export const authMiddleware = createMiddleware<{
    Bindings: Bindings;
    Variables: Variables;
}>(async (c, next) => {
    const authorization = c.req.header('Authorization');

    if (!authorization) {
        return c.json(
            { message: 'Authorization header is required' },
            401
        );
    }

    const [scheme, token] = authorization.split(' ');

    if (scheme !== 'Bearer' || !token) {
        return c.json(
            { message: 'Invalid authorization format' },
            401
        );
    }

    try {
        const payload = await verify(
            token,
            c.env.JWT_SECRET,
            'HS256'
        );

        c.set('jwtPayload', payload as Variables['jwtPayload']);

        await next();
    } catch {
        return c.json(
            { message: 'Invalid or expired token' },
            401
        );
    }
});