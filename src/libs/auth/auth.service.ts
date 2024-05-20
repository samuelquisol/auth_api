import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { HashService } from './utils/services/hash.service';
import { SignUpDto, LogInDto } from './data-standardizers/dtos';
import { JwtPayload, Tokens } from './data-standardizers/types';
import { UserService } from '../../module/users/users.service'
import { ValidRoles } from './data-standardizers/roles-management/valid-roles';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly hashService: HashService,
  ) {}

  public async logIn(logInDto: LogInDto): Promise<Tokens> {
    const { email, password } = logInDto;
    const user = await this.userService.findOneByEmail(email);
    this.validateUserAndPassword(user, password);
    return this.getTokens({ sub: user.id });
  }

  public async logOut(email: string): Promise<Tokens> {
    const user = await this.userService.findOneByEmail(email);
    const Access_token = await this.getTokens({ sub: user.id });

    if (!Access_token) {
      throw new BadRequestException('No active session to log out from');
    }

    const expiresIn = '5s';
    const logOutToken = await this.getTokens({ sub: user.id }, expiresIn);

    return logOutToken;
  }

  public async signUp(userSignUp: SignUpDto): Promise<Tokens> {
    const { email, password } = userSignUp;
    await this.validateEmailForSignUp(email);
    const hashedPassword = await this.hashService.hash(password);
    const user = await this.userService.create({ email, password: hashedPassword, role: ValidRoles.USER });
    return this.getTokens({ sub: user.id });
  }

  private async getTokens(payload: JwtPayload, expiresIn?: string): Promise<Tokens> {
    const secretKey = process.env.JWT_SECRET;
    if (!secretKey) {
      throw new Error('JWT_SECRET is not set');
    }

    const options = { secret: secretKey };
    
    if (expiresIn) {
      options['expiresIn'] = expiresIn;
      const accessToken = await this.jwtService.signAsync(payload, options);
      return { access_token: accessToken, expiresIn};  
    }

    const accessToken = await this.jwtService.signAsync(payload, options);
    return { access_token: accessToken };
  }

  private async validateUserAndPassword(user: Partial<LogInDto>, password: string): Promise<void> {
    if (!user || !(await this.hashService.compare(password, user.password))) {
      throw new BadRequestException('Invalid email or password');
    }
  }

  private async validateEmailForSignUp(email: string): Promise<void> {
    const user = await this.userService.findOneByEmail(email);
    if (user) {
      throw new BadRequestException('Email already exists');
    }
  }
}
