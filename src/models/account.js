const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const AccountSchema = new mongoose.Schema({
    firstname: {
        type: String,
        trim: true,
        required: true
    },
    lastname: {
        type: String,
        trim: true,
        required: true
    },
    email: {
        type: String,
        trim: true,
        required: true
    },
    password: {
        type: String,
        trim: true,
        required: true
    },
    createdDate: Date
});

// hash user password before saving into database
AccountSchema.pre('save', function (next) {
    if (!this.createdDate) {
        this.createdDate = new Date();
    }
    this.password = bcrypt.hashSync(this.password, 10);
    next();
});

module.exports = mongoose.model('Account', AccountSchema);