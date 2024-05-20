import { AuthService } from './auth.service';
import { Controller, Post, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { LogInDto, SignUpDto } from './data-standardizers/dtos/index';
import {
  ApiBadRequestResponse,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Authenticate user' })
  @ApiCreatedResponse({ description: 'User successfully logged in' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiBadRequestResponse({ description: 'Invalid request' })
  @ApiInternalServerErrorResponse({ description: 'Internal server error' })
  @HttpCode(HttpStatus.OK)
  @Post('login')
  login(@Body() dto: LogInDto) {
    return this.authService.logIn(dto);
  }

  @ApiOperation({ summary: 'Log out user' })
  @ApiCreatedResponse({ description: 'User successfully logged out' })
  @ApiNotFoundResponse({ description: 'Resource not found' })
  @ApiBadRequestResponse({ description: 'Invalid request' })
  @ApiInternalServerErrorResponse({ description: 'Internal server error' })
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  async logOut(email: string): Promise<{ access_token: string }> {
    const token = await this.authService.logOut(email);
    return token;
  }

  @ApiOperation({ summary: 'Sign up user' })
  @ApiCreatedResponse({ description: 'User successfully registered' })
  @ApiNotFoundResponse({ description: 'Resource not found' })
  @ApiBadRequestResponse({ description: 'Invalid request' })
  @ApiInternalServerErrorResponse({ description: 'Internal server error' })
  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  signUp(@Body() dto: SignUpDto) {
    return this.authService.signUp(dto);
  }

}
