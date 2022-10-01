import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { GetCurrentUser, PublicRoute } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @PublicRoute()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  async signupLocal(@Body() body: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(body);
  }

  @PublicRoute()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  async signinLocal(@Body() body: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(body);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@GetCurrentUser('sub') userId: number) {
    return this.authService.logout(userId);
  }

  @PublicRoute()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshTokens(@GetCurrentUser() authUser: any): Promise<Tokens> {
    return this.authService.refreshTokens(authUser.sub, authUser.refreshTokens);
  }
}
