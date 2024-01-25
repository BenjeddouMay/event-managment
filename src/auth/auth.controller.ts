import { Controller, Get, Post, Body, Patch, Param, Delete, Query, BadRequestException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ParticipantSubscribeDto } from './dto/participant-subscribe.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post('signup/?role')
  async signUp(
    @Query('role') role: string,
    @Body() signUpDto: ParticipantSubscribeDto
  ) {
    if (role !== 'Person' && role !== 'ADMIN') {
      throw new BadRequestException('Invalid role specified');
    }

    return this.authService.signUp(signUpDto, role as 'Person' | 'ADMIN');
  }
}
/*
  @Post()
  create(@Body() createAuthDto: CreateAuthDto) {
    return this.authService.create(createAuthDto);
  }

  @Get()
  findAll() {
    return this.authService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }*/

