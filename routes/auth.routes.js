const{Router} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()

// /api/auth/register
router.post('/register',
    [
        check('email', 'Incorrect email entry').isEmail(),
        check('password', 'Minimal password length is 6 characters!').isLength({ min: 6 })
    ],
    async (req, res) => {
    try {
        const errors = validationResult(req)

        if ( !errors.isEmpty() ) {
            return res.status(400).json({ errors: errors.array(), message: 'Incorrect data entry...' })
        }

        const {email, password} = req.body
        const candidate = await User.findOne({email})

        if(candidate) {
           return res.status(400).json({message: 'This email has been registered by another user...'})
        }

        const hashedPassword = await bcrypt.hash(password, 12)
        const user = new User({ email, password: hashedPassword })

        await user.save()

        res.status(201).json({ message: 'User was created successfully' })



    } catch (e) {
        res.status(500).json({message: "Something went wrong..."})
    }
    }
)

// /api/auth/login
router.post(
    '/login',
    [
        check('email', 'Please, enter popper email').normalizeEmail().isEmail(),
        check('password', 'Please, enter your password').exists()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req)

            if (!errors.$isEmpty()) {

                return res.status(400).json({

                    errors: errors.array(),
                    message: 'Incorrect data entry...'
                })
            }

            const {email, password} = req.body
            const user = await User.findOne({email})

            if(!user) {
                return res.status(400).json({ message: 'User was not found'})
            }

            const isMatch = await bcrypto.compare(password, user.password)

            if (!isMatch) {
                return res.stat(400).json({ message: 'Incorrect password'})
            }
            const token = jwt.sign(
                {userId: user.id},
                config.get('jwtSecret'),
                { expiresIn: '1h' }
            )

            res.json({ token, userId: user.id })



        } catch (e) {
            res.stat(500).json({message: 'Something went wrong...'})

        }

    }
)


module.exports = router
