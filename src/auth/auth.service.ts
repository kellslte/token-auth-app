import { CreateUserDto } from './../users/dto/create-user.dto';
import { UsersService } from './../users/users.service';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import * as dotenv from 'dotenv';

dotenv.config();

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async signUp(body: CreateUserDto): Promise<any> {
    // check if user already exists
    const existingRecord = await this.usersService.findByUsername(
      body.username,
    );

    if (existingRecord)
      throw new HttpException(
        'User record already exists',
        HttpStatus.BAD_REQUEST,
      );

    // hash user password
    const hash = await argon.hash(body.password);

    const userRecord = await this.usersService.create({
      ...body,
      password: hash,
    });

    const tokens = await this.getTokens(userRecord._id, userRecord.username);

    await this.updateRefreshToken(userRecord._id, tokens.refreshToken);

    return tokens;
  }

  async signIn(body: AuthDto) {
    // check if user exists
    const user = await this.usersService.findByUsername(body.username);

    if (!user)
      throw new HttpException(
        'User record does not exist',
        HttpStatus.NOT_FOUND,
      );

    const matchedPassword = await argon.verify(user.password, body.password);

    if (!matchedPassword)
      throw new HttpException(
        'Invalid username or password',
        HttpStatus.UNAUTHORIZED,
      );

    const tokens = await this.getTokens(user._id, user.username);

    await this.updateRefreshToken(user._id, tokens.refreshToken);

    return tokens;
  }

  async logout(id: string) {
    return this.usersService.update(id, { refreshToken: null });
  }

  async refreshToken(id: string, refreshToken: string) {
    const user = await this.usersService.findById(id);

    if (!user || !user.refreshToken)
      throw new HttpException('Unauthorized access', HttpStatus.FORBIDDEN);

    const matchedRefreshToken = await argon.verify(
      user.refreshToken,
      refreshToken,
    );

    if (!matchedRefreshToken)
      throw new HttpException('Unauthorized access', HttpStatus.FORBIDDEN);

    const tokens = await this.getTokens(user._id, user.username);

    await this.updateRefreshToken(user._id, tokens.refreshToken);

    return tokens;
  }

  // helpers
  async getTokens(id: string, username: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: id,
          username,
        },
        {
          secret: process.env.JWT_ACCESS_TOKEN_KEY,
          expiresIn: '15m',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: id,
          username,
        },
        {
          secret: process.env.JWT_REFRESH_TOKEN_KEY,
          expiresIn: '7d',
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async updateRefreshToken(id: string, refreshToken: string) {
    const hash = await argon.hash(refreshToken);

    await this.usersService.update(id, {
      refreshToken: hash,
    });
  }
}
