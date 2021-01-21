const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { UserInputError } = require('apollo-server');

const { validateLoginInput } = require('../../util/validators.js')
const { validateRegisterInput } = require ('../../util/validators.js')
const { SECRET_KEY } = require('../../config');
const User = require('../../models/User');

function generateToken(user){
    return jwt.sign({
        id: user.id,
        email: user.email,
        username: user.username
    }, SECRET_KEY, { expiresIn: '1h'});
}
module.exports = {
    Mutation: {
        async login(_, { username, password }){
            const {errors, valid} = validateLoginInput(username, password);
            const user = await User.findOne({ username });


            if(!valid){
                throw new UserInputError('Errors', { errors });
            }
            if(!user){
                errors.general = 'User not found'
                throw new UserInputError('User not found', { errors });
            } 
            const match = await bcrypt.compare(password, user.password);
            if(!match) {
                errors.general = 'Wrong Credentials'
                throw new UserInputError('Wrong Credentials', { errors });
            }

            const token = generateToken(user)
            return {
                ...user._doc,
                id: user._id,
                token
            }
        },
        //args is RegisterInput from typeDefs.js
        async register(_, { 
            registerInput:  { username, email, password, confirmPassword }
        }, 
        ) {
            // TODO: Validate user data
            const { valid, errors } = validateRegisterInput(username, email, password, confirmPassword);
            if(!valid) {
                throw new UserInputError('Errors', { errors })
            }
            //       Make sure user doesn;t already exist
            const user = await User.findOne({ username });
            if(user){
                throw new UserInputError("Username is already in use", {
                    errors: {
                        username: 'This username is already in use'
                    }
                })
            }
            //       Hash password and create an auth token
            password = await bcrypt.hash(password, 12);

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            });

            const res = await newUser.save();

            const token = generateToken(res)
            return {
                ...res._doc,
                id: res._id,
                token
            }
        }
    }
}