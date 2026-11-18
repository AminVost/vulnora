import postgres from 'postgres';
let client: ReturnType<typeof postgres> | undefined;
export function db() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_NOT_CONFIGURED');
  if (!client) client = postgres(process.env.DATABASE_URL, { max: 3, idle_timeout: 20, connect_timeout: 10, ssl: 'require', prepare: false });
  return client;
}
