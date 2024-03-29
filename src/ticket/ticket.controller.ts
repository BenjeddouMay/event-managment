import { Controller, Get, Post, Body, Patch, Param, Delete, Req, UseGuards } from '@nestjs/common';
import { TicketService } from './ticket.service';
import { CreateTicketDto } from './dto/create-ticket.dto';
import { UpdateTicketDto } from './dto/update-ticket.dto';

@Controller('ticket')
export class TicketController {
  constructor(private readonly ticketService: TicketService) { }

  @Post()
  create(@Body() createTicketDto: CreateTicketDto) {
    return this.ticketService.create(createTicketDto);
  }

  @Get()
  findAll() {
    return this.ticketService.findAll();
  }

  //@UseGuards(JwtAuthGuard)
  @Get('/purchaser')
  async findTicketsByPurchaser(@Req() req) {
    const purchaserId = req.user.id;
    const tickets = await this.ticketService.findTicketsByPurchaser(purchaserId);
    return tickets;
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.ticketService.findOne(+id);
  }

  //@UseGuards(JwtAuthGuard)
  @Post('/buy/:eventId')
  async buyTicket(@Req() req, @Param('eventId') eventId: number) {
    const participant = req.user;
    const ticket = await this.ticketService.buyTicket(participant, eventId);
    return ticket;
  }

  //@UseGuards(JwtAuthGuard)
  @Post('/reserve/:eventId')
  async reserveTicket(@Req() req, @Param('eventId') eventId: number) {
    const participant = req.user;
    const ticket = await this.ticketService.reserveTicket(participant, eventId);
    return ticket;
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateTicketDto: UpdateTicketDto) {
    return this.ticketService.update(+id, updateTicketDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.ticketService.remove(+id);
  }
}
