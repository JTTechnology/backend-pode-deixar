import { IsEmail, IsEnum, IsNotEmpty, IsString, Matches } from 'class-validator';

export class RegisterDto {
  @IsString()
  @IsNotEmpty()
  complete_name: string;

  @IsEmail()
  email: string;

  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/,
    {
      message:
        'weak password: minimun 8 characters, 1 upper, 1 lower, 1 number e 1 especial',
    },
  )
  password: string;

  @IsString()
  @IsNotEmpty()
  phone: string;

  @IsString()
  postal_code: string;

  @IsEnum(['CLIENT', 'PROVIDER'])
  role: 'CLIENT' | 'PROVIDER';
}
