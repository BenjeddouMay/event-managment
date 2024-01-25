import { BadRequestException, ConflictException, Injectable, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import {  Repository } from "typeorm";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from 'bcrypt';
import { ParticipantSubscribeDto } from "./dto/participant-subscribe.dto";
import { LoginCredentialsDto } from "./dto/login-credentials.dto";
import { ConfigService } from "@nestjs/config";
import { Person } from "../entities/person.entity";
import { Admin } from "../entities/admin.entity";

import { Role } from "../enum/role.enum";


@Injectable()
export class AuthService {
 private jwtSecret: string;
  constructor(
    @InjectRepository(Person)
    private readonly personRepo: Repository<Person>,

    @InjectRepository(Admin)
    private readonly adminRepo: Repository<Admin>,

    private jwtService: JwtService,
    private configService: ConfigService,
  
  ) {
    this.jwtSecret = this.configService.get<string>('JWT_SECRET');
  }

  async signUp(signUpDto: ParticipantSubscribeDto, role: 'Person' | 'ADMIN'): Promise<Person | Admin> {
    const email = signUpDto.email;
    

    if (role === 'Person') {
      const existingPerson = await this.personRepo.findOne({ where: { email } });

      if (existingPerson) {
        throw new ConflictException('A person with this email already exists.');
      }

      const newPerson = this.personRepo.create({
        ...signUpDto
      });
      newPerson.salt = await bcrypt.genSalt();
      newPerson.password = await bcrypt.hash(newPerson.password, newPerson.salt);
      await this.personRepo.save(newPerson);
      delete newPerson.salt;
    delete newPerson.password;
      return newPerson;  
    } 
    
    
    
    
    
    else {
      const existingAdmin = await this.adminRepo.findOne({
        where: { email: email }
      });
      
      if (existingAdmin) {
        throw new ConflictException('An admin with this email already exists.');
      }

      const newAdmin = this.adminRepo.create({
        ...signUpDto
      });
      newAdmin.salt = await bcrypt.genSalt();
      newAdmin.password = await bcrypt.hash(newAdmin.password, newAdmin.salt);
      await this.adminRepo.save(newAdmin);
      delete newAdmin.password;
      delete newAdmin.salt;
      return newAdmin;  // Omit sensitive info as needed
    }
  }



/*
  async register(participantData: ParticipantSubscribeDto): Promise<Partial<Person>> {

    const email= participantData.email;
    const existingParticipant = await this.personRepo.createQueryBuilder('person')
      .where('person.email = :email', { email })
      .andWhere('(person.role = :participant OR person.role = :creator)', {
        participant: Role.PARTICIPANT,
        creator: Role.CREATOR,
      })
      .getOne();
    if (existingParticipant) {
      throw new ConflictException('An account with this email already exists.');
    }

    const participant = this.personRepo.create({
      ...participantData
    })
    participant.salt = await bcrypt.genSalt();
    participant.password = await bcrypt.hash(participant.password, participant.salt);
    await this.personRepo.save(participant);
    delete participant.salt;
    delete participant.password;
    return participant;
  }

  /*

  async login(credentials: LoginCredentialsDto) {
    if (!credentials || !credentials.email || !credentials.password) {
      throw new BadRequestException('Invalid credentials provided.');
    }
    const { email, password } = credentials;
    const participant = await this.participantRepository.findOne({ where: { email: email } });
    if (!participant) {
      throw new NotFoundException('Email or password incorrect.');
    }
    const hashedPassword = await bcrypt.hash(password, participant.salt);
    console.log('match : ', participant.password === hashedPassword)
    if (participant.password === hashedPassword) {
      const payload = {
        name: participant.name,
        firstname: participant.firstname,
        email: participant.email,
        role: participant.role
      };
      console.log(process.env.JWT_SECRET);
      const jwt = this.jwtService.sign(payload, {
        secret: this.jwtSecret,
        expiresIn: '1d',
      });
      return {
        "access_token": jwt,
      };
    } else {
      throw new NotFoundException('Email or password incorrect.');
    }
  }*/
}