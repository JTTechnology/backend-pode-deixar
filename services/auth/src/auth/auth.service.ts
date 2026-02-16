import { Injectable, UnauthorizedException, ConflictException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(dto: RegisterDto) {
    // Verificar se o email já existe
    const existingUser = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existingUser) {
      throw new ConflictException('Email já cadastrado');
    }

    // Hash da senha
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(dto.password, saltRounds);

    // Criar usuário no banco
    const user = await this.prisma.user.create({
      data: {
        completeName: dto.complete_name,
        email: dto.email,
        password: passwordHash,
        role: dto.role,
        phone: dto.phone,
        postalCode: dto.postal_code,
      },
      select: {
        id: true,
        completeName: true,
        email: true,
        role: true,
        phone: true,
        postalCode: true,
        createdAt: true,
      },
    });

    return {
      message: 'user successfully registered',
      user: {
        id: user.id,
        complete_name: user.completeName,
        email: user.email,
        role: user.role,
        phone: user.phone,
        postal_code: user.postalCode,
        created_at: user.createdAt,
      },
    };
  }

  async login(dto: LoginDto) {
    // Buscar usuário pelo email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (!user) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    // Verificar senha
    const isPasswordValid = await bcrypt.compare(dto.password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Credenciais inválidas');
    }

    // Gerar JWT com informações do usuário
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = await this.jwtService.signAsync(payload);

    return {
      message: 'successfully made login',
      access_token: accessToken,
      user: {
        id: user.id,
        complete_name: user.completeName,
        email: user.email,
        role: user.role,
      },
    };
  }
}