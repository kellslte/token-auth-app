import { User, UserDocument } from './../schema/user.schema';
import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Model } from 'mongoose';

@Injectable()
export class UsersService {
  constructor(@InjectModel(User.name) private user: Model<UserDocument>) {}

  async create(createUserDto: CreateUserDto): Promise<UserDocument> {
    const createdUser = new this.user(createUserDto);

    return createdUser.save();
  }

  async findAll(): Promise<UserDocument[]> {
    return this.user.find().exec();
  }

  async findById(id: string): Promise<UserDocument> {
    return this.user.findById(id);
  }

  async findByUsername(username: string): Promise<UserDocument> {
    return this.user.findOne({ username }).exec();
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
  ): Promise<UserDocument> {
    return this.user.findByIdAndUpdate(id, updateUserDto, { new: true }).exec();
  }

  async remove(id: string): Promise<UserDocument> {
    return this.user.findByIdAndDelete(id).exec();
  }
}
