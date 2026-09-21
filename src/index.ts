import { Hono } from 'hono'
import { sign } from 'hono/jwt';
import { hashPassword } from './utils/hashPassword';
import { comparePassword } from './utils/comparePassword';
import type { Bindings } from './types/types';
import { authMiddleware } from './middleware/auth';
import { cors } from 'hono/cors'

const app = new Hono<{ Bindings: Bindings }>();

app.use(
  '*',
  cors({
    origin: 'https://tanstack-start-practice-auth-service.mikeonlinemx.workers.de',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  }),
)

app.post('/auth/register', async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json({ message: 'Email and password are required' }, 400);
  }

  // Aquí deberías generar el hash de password
  const passwordHash = await hashPassword(password);

  const result = await c.env.DB
    .prepare(`
      INSERT INTO users (email, password_hash)
      VALUES (?, ?)
    `)
    .bind(email, passwordHash)
    .run();

  return c.json({
    success: result.success
  });
});

app.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json(
      { message: 'Email and password are required' },
      400
    );
  }

  const user = await c.env.DB
    .prepare(`
      SELECT *
      FROM users
      WHERE email = ?
    `)
    .bind(email)
    .first<{
      id: number;
      email: string;
      password_hash: string;
    }>();

  if (!user) {
    return c.json(
      { message: 'Invalid credentials' },
      401
    );
  }

  const isMatch = await comparePassword(
    password,
    user.password_hash
  );

  if (!isMatch) {
    return c.json(
      { message: 'La contraseña es incorrecta' },
      401
    );
  }

  if (!c.env.JWT_SECRET) {
    return c.json(
      { message: 'JWT secret is not configured' },
      500
    );
  }

  const token = await sign(
    {
      sub: String(user.id),
      email: user.email,
      exp: Math.floor(Date.now() / 1000) + 60 * 60
    },
    c.env.JWT_SECRET
  );

  return c.json({
    message: 'Login successful',
    token
  });
});

app.get(
  '/ping',
  authMiddleware,
  async (c) => {
    const user = c.get('jwtPayload');

    return c.json({
      id: user.sub,
      email: user.email,
      exp: new Date(user.exp * 1000).toLocaleString('es-MX', {
        timeZone: 'America/Mexico_City'
      })
    });
  }
);

export default app
