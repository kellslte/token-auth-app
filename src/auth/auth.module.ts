import { UsersModule } from './../users/users.module';
import { RefreshTokenStrategy } from './strategy/refeshtoken.strategy';
import { AccessTokenStrategy } from './strategy/accesstoken.strategy';
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [JwtModule.register({}), UsersModule],
  controllers: [AuthController],
  providers: [AuthService, AccessTokenStrategy, RefreshTokenStrategy],
})
export class AuthModule {}
