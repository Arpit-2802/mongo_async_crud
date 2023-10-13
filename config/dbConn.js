const mongoose = require('mongoose');
const DATABASE_URI="mongodb://0.0.0.0:27017";
const connectDB = async () => {
    try {
        await mongoose.connect(DATABASE_URI, {
            useUnifiedTopology: true,
            useNewUrlParser: true
        });
    } catch (err) {
        console.error(err);
    }
}

module.exports = connectDB