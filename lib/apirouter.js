const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const logger = require('winston');
const config = require('./config');
const redisClient = require('./redisclient');
const AccountModel = require('./models/account');

const _generateTokens = async dbAccount => {
    const { _id, password, ...account } = dbAccount;
    const refreshToken = jwt.sign({ account }, config.REFRESH_TOKEN_SECRET);
    const accessToken = jwt.sign({ account }, config.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
    const payload = jwt.verify(accessToken, config.ACCESS_TOKEN_SECRET);
    const accessTokenExpiry = payload.exp;

    // save tokens
    await redisClient.set(refreshToken, accessToken);

    return {
        refreshToken,
        accessToken,
        accessTokenExpiry
    }
}

const _refreshTokens = async oldRefreshToken => {
    const oldAccessToken = await redisClient.get(oldRefreshToken);
    if (!oldAccessToken) {
        logger.error('refresh token not found in database');
        return {};
    }

    let account;
    try {
        payload = jwt.verify(oldRefreshToken, config.REFRESH_TOKEN_SECRET);
        if (payload && payload.account) {
            account = payload.account;
        }
    } catch (exc) {
        logger.error(exc);
    }
    await _clearTokens(oldRefreshToken);

    if (!account) {
        return {};
    }

    return await _generateTokens(account);
}

const _clearTokens = async refreshToken => {
    await redisClient.del(refreshToken);
}

const apiRouter = express.Router();

apiRouter.post('/signup', async (req, res) => {
    try {
        const { firstname, lastname, email, password } = req.body;
        if ([firstname, lastname, email, password].some(el => !el)) {
            return res.status(422).json({ error: 'missing fields' });
        }
        const existingAccount = await AccountModel.findOne({ email: email.toLowerCase() });
        if (existingAccount) {
            return res.sendStatus(409);
        }
        await AccountModel.create({ firstname, lastname, email, password });
        res.sendStatus(201);
    } catch (exc) {
        res.sendStatus(500);
    }
});

apiRouter.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            logger.info('login failed some fields are missing');
            return res.status(422).json({ error: 'missing fields' });
        }

        const account = await AccountModel.findOne({ email: email.toLowerCase() });
        if (!account) {
            logger.info(`login failed for ${email} account not found`);
            return res.sendStatus(401);
        }

        const validPassword = await bcrypt.compare(password, account.password);
        if (!validPassword) {
            logger.info(`login failed for ${email} bad password`);
            return res.sendStatus(401);
        }

        const { refreshToken, accessToken, accessTokenExpiry } = await _generateTokens(account.toObject());

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
        const { refreshToken, accessToken, accessTokenExpiry } = await _refreshTokens(oldRefreshToken);
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

apiRouter.delete('/signout', async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    logger.debug(`remove the refresh token: ${refreshToken}`);
    if (!refreshToken) {
        return res.sendStatus(202);
    }

    try {
        await _clearTokens(refreshToken);
        res.sendStatus(204);
    } catch (exc) {
        logger.error(exc);
        res.sendStatus(500)
    }
});

module.exports = apiRouter