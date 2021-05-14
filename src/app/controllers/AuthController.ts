import { Request, Response } from 'express';
import { getRepository } from 'typeorm';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

import User from '../models/User';

class AuthController{
  async authenticate(req: Request, res: Response){
        const repository = getRepository(User);
        const { email, password } = req.body;
        const user = await repository.findOne({ where: { email }});

        if(!user){
            return res.send(409);
        }

        const isValidPassword = bcrypt.compare( password, user.password);
        
        if(!isValidPassword){
            return res.sendStatus(401);
        }

        const token = jwt.sign({id: user.id}, 'secret', {expiresIn: '1d'});  
//para não retornar o password através de delete user.password, retornei id e email dentro de um array
        return res.json({
            user: [
                user.id,
                user.email,
            ],
            token,
        });
    }
}

export default new AuthController();