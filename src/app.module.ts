import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import dbConfig from './libs/persistence/db-config';
import { PersistenceModule } from './libs/persistence';
/* import { UsersModule } from '';
 */
/* import { AtGuard } from '';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from '';
 */

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: '.env',
      load: [dbConfig],
      isGlobal: true,
    }),
    PersistenceModule,
    /* AuthModule, */
    /* UsersModule, */
  ],
  controllers: [],
  providers: [
    /* {
      provide: APP_GUARD,
      useClass: AtGuard,
    }, */
  ],
})
export class AppModule {}
