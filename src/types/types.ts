export type Bindings = {
  DB: D1Database;
  JWT_SECRET: string;
};

export type Variables = {
  jwtPayload: {
    sub: string;
    email: string;
    exp: number;
  };
};