import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
  ) {}

  async signupLocal(body: AuthDto): Promise<Tokens> {
    const checkUser = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });

    if (checkUser) {
      throw new ForbiddenException('User already exists');
    }

    const hash = this.hashData(body.password);

    let user;

    try {
      user = await this.prisma.user.create({
        data: {
          email: body.email,
          hash,
        },
      });
    } catch (error: any) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials incorrect');
        }
        throw error;
      }
    }

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async signinLocal(body: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: body.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Invalid credentials');
    }

    const isMatch = bcrypt.compareSync(body.password, user.hash);

    if (!isMatch) {
      throw new ForbiddenException('Invalid credentials');
    }

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshTokens(userId: number, refreshToken: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access denied');
    }

    const rtMatches = await bcrypt.compare(refreshToken, user.hashedRt);

    if (!rtMatches) {
      throw new ForbiddenException('Access denied');
    }

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  hashData(data: string) {
    return bcrypt.hashSync(data, 10);
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        { secret: this.config.get<string>('AT_SECRET'), expiresIn: '15m' },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.config.get<string>('RT_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);

    return { access_token: at, refresh_token: rt };
  }

  async updateRtHash(userId: number, rt: string) {
    const hash = this.hashData(rt);

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }
}
