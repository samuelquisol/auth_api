import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  Length,
  Matches,
} from 'class-validator';
import { Document } from 'mongoose';
import { ValidRoles } from '../valid-roles';

@Schema({ timestamps: true })
export class User extends Document {
  @IsOptional()
  @IsString()
  @Length(3, 50)
  @Prop({ required: true })
  username?: string;

  @IsNotEmpty()
  @IsEmail()
  @Transform(({ value }) => value.toLowerCase())
  @Prop({ required: true })
  email: string;

  @IsNotEmpty()
  @IsString()
  @Length(8, 50)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/, {
    message: 'password too weak',
  })
  @Prop({ required: true })
  password: string;

  @IsOptional()
  @IsEnum(ValidRoles)
  @Prop({ type: String, enum: ValidRoles, default: ValidRoles.USER })
  role: ValidRoles;
}

export const UserSchema = SchemaFactory.createForClass(User);
