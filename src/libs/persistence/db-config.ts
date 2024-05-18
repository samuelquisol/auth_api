import { registerAs } from '@nestjs/config';

export default registerAs('dbConfig', () => {
  const dbConfig = {
    db: process.env.URI_DB,
  };
  return dbConfig;
});
