import { Controller, Get, Post, Body, Patch, Param, Delete, UseInterceptors, UploadedFile } from '@nestjs/common';
import { ImageService } from './image.service';
import { CreateImageDto } from './dto/create-image.dto';
import { FileInterceptor } from '@nestjs/platform-express';


@Controller('image')
export class ImageController {
  constructor(private readonly imageService: ImageService) {}

  @Post('upload')
  @UseInterceptors(FileInterceptor('file'))
  async uploadImage(@UploadedFile() file: any): Promise<any> {
    if (!file) {
      return { success: false, message: 'No file uploaded' };
    }

    const bufferData = Buffer.from(file.buffer);

    try {
      const createImageDto: CreateImageDto = { data: bufferData };
      const createdImage = await this.imageService.create(createImageDto);
      return { success: true, image: createdImage };
    } catch (error) {
      return { success: false, message: 'Failed to upload image' };
    }
  }

  @Get('event/:eventId')
  async getImagesByEvent(@Param('eventId') eventId: number) {
      return this.imageService.findByEventId(eventId);
  }

}
