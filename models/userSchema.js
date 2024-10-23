import mongoose from 'mongoose'; // Use import for ES modules

const userSchema = new mongoose.Schema({
    uname: {
        type: String,
        required: true,
        unique: true
    },
    pwd: {
        type: String,
        required: true
    },
    uuid: {
        type: String,
        required: true,
        unique: true
    }
});

const User = mongoose.model('User', userSchema);

export default User; // Export as default
