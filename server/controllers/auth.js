const { connect } = require('getstream');
const bcrypt = require('bcrypt');
const StreamChat = require('stream-chat').StreamChat;
const crypto = require('crypto');

require('dotenv').config();

const api_key = process.env.STREAM_API_KEY;
const api_secret = process.env.STREAM_API_SECRET;
const app_id = process.env.STREAM_APP_ID;

const signup = async (req, res) => {
    try {
        const { fullName, username, password, phoneNumber } = req.body;

        const userId = crypto.randomBytes(16).toString('hex');

        const serverClient = connect(api_key, api_secret, app_id);

        const hashedPassword = await bcrypt.hash(password, 10);

        // Create the user in Stream
        await serverClient.upsertUser({
            id: userId,
            name: username,
            fullName: fullName,
            hashedPassword: hashedPassword,
            phoneNumber: phoneNumber,
        });

        const token = serverClient.createUserToken(userId);

        res.status(200).json({ token, fullName, username, userId, hashedPassword, phoneNumber });
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: error });
    }
};

const login = async (req, res) => {
    try {
        const { username, password } = req.body;

        const serverClient = connect(api_key, api_secret, app_id);
        const client = StreamChat.getInstance(api_key, api_secret);

        const { users } = await client.queryUsers({ name: username });

        if (!users.length) {
            console.log('User not found');
            return res.status(400).json({ message: 'User not found' });
        }

        const success = await bcrypt.compare(password, users[0].hashedPassword);

        if (success) {
            // Use serverClient to create the token
            const token = serverClient.createUserToken(users[0].id);
            res.status(200).json({
                token,
                fullName: users[0].fullName,
                username,
                userId: users[0].id,
            });
        } else {
            console.log('Incorrect password');
            res.status(401).json({ message: 'Incorrect password' });
        }
    } catch (error) {
        console.log('Error in Login:', error);
        res.status(500).json({ message: error.message || error });
    }
};




module.exports = { signup, login }