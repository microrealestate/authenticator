const express = require('express');
const jwt = require('jsonwebtoken');
const logger = require('winston');
const config = require('./config');
const redisClient = require('./redisclient');
const AccountModel = require('./models/account')

const generateTokens = async email => {
    const user = { email };

    const refreshToken = jwt.sign(user, config.REFRESH_TOKEN_SECRET);
    const accessToken = jwt.sign(user, config.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
    const accessTokenExpiry = 111111; //TODO

    // save tokens
    await redisClient.set(refreshToken, accessToken);

    return {
        refreshToken,
        accessToken,
        accessTokenExpiry
    }
}

const refreshTokens = async oldRefreshToken => {
    const oldAccessToken = await redisClient.get(oldRefreshToken);
    if (!oldAccessToken) {
        logger.error('refresh token not found in database');
        return {};
    }

    let payload;
    try {
        payload = jwt.verify(oldRefreshToken, config.REFRESH_TOKEN_SECRET);
    } catch (exc) {
        logger.error(exc);
        return {};
    }

    await clearTokens(oldRefreshToken);

    // get email from oldAccessToken
    const email = payload.email;
    return generateTokens(email);
}

const clearTokens = async refreshToken => {
    await redisClient.del(refreshToken);
}

const apiRouter = express.Router();

apiRouter.post('/register', async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;
        await AccountModel.create({ firstname, lastname, email, password });
        res.sendStatus(201);
    } catch (exc) {
        res.sendStatus(500);
    }
});

apiRouter.get('/users', async (req, res) => {
    try {
        const users = await AccountModel.find();
        res.json(users);
    } catch (exc) {
        res.sendStatus(500);
    }
});

apiRouter.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // TODO make the authentication

    try {
        const { refreshToken, accessToken, accessTokenExpiry } = await generateTokens(email);

        logger.debug(`create a new refresh token ${refreshToken}`);
        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        res.json({
            accessToken,
            accessTokenExpiry
        });
    } catch (exc) {
        logger.error(exc);
        res.sendStatus(500);
    }
});

apiRouter.post('/refreshToken', async (req, res) => {
    const oldRefreshToken = req.cookies.refreshToken;
    logger.debug(`give a new refresh token for ${oldRefreshToken}`);
    if (!oldRefreshToken) {
        return res.sendStatus(401);
    }

    try {
        const { refreshToken, accessToken, accessTokenExpiry } = await refreshTokens(oldRefreshToken);
        if (!refreshToken) {
            return res.sendStatus(403);
        }

        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        res.json({
            accessToken,
            accessTokenExpiry
        });
    } catch (exc) {
        logger.error(exc);
        res.sendStatus(500);
    }

});

apiRouter.delete('/logout', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    logger.debug(`remove the refresh token: ${refreshToken}`);
    if (!refreshToken) {
        return res.sendStatus(202);
    }

    try {
        await clearTokens(refreshToken);
        res.sendStatus(204);
    } catch (exc) {
        logger.error(exc);
        res.sendStatus(500)
    }
});

module.exports = apiRouter