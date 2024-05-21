import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Query,
  ParseUUIDPipe,
  Delete,
} from '@nestjs/common';
import { CreateUserDto } from './data-standardizers/dtos/create-user.dto';
import { UpdateUserDto } from './data-standardizers/dtos/update-user.dto';
import { PaginationDto } from './data-standardizers/dtos/pagination.dto';
import { ValidRoles } from './data-standardizers/valid-roles';
/* import { Auth } from ''; */
import { UserService } from './users.service';
import {
  ApiBadRequestResponse,
  ApiCreatedResponse,
  ApiInternalServerErrorResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly userService: UserService) {}

  @ApiOperation({ summary: 'Create user' })
  @ApiCreatedResponse({ description: 'User created successfully' })
  @ApiBadRequestResponse({ description: 'Invalid data provided' })
  @Post()
  create(@Body() dto: CreateUserDto) {
    return this.userService.create(dto);
  }

  /* @Auth(!ValidRoles.USER) */
  @ApiOperation({ summary: 'Get all users' })
  @ApiOkResponse({ description: 'List of users retrieved successfully' })
  @ApiNotFoundResponse({ description: 'No users found' })
  @Get()
  findAll(@Query() dto: PaginationDto) {
    return this.userService.findAll(dto);
  }

  /* @Auth() */
  @ApiOperation({ summary: 'Update user' })
  @ApiOkResponse({ description: 'User updated successfully' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiBadRequestResponse({ description: 'Invalid data provided' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Server error' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @Patch(':id')
  async updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return this.userService.update(id, updateUserDto);
  }

  /* @Auth() */
  @ApiOperation({ summary: 'Delete user' })
  @ApiOkResponse({ description: 'User deleted successfully' })
  @ApiNotFoundResponse({ description: 'User not found' })
  @ApiUnauthorizedResponse({ description: 'Unauthorized' })
  @ApiInternalServerErrorResponse({ description: 'Server error' })
  @ApiParam({ name: 'id', description: 'User ID' })
  @Delete(':id')
  removeUser(@Param('id', ParseUUIDPipe) id: string) {
    return this.userService.remove(id);
  }

}
