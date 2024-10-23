import mongoose from 'mongoose';

const cabBookingSchema = new mongoose.Schema({
    name: { type: String, required: true },
    city: { type: String, required: true },
    source: { type: String, required: true },
    destination: { type: String, required: true },
    weight: { type: Number, required: true },
    vtype: { type: String, required: true },
    date: { type: Date, required: true },
    cost: { type: Number, required: true },
    status: { type: String, default: 'upcoming' },
    uuid: { type: String, required: true }, 
    otp: { type: String, required: false },
});

const CabBooking = mongoose.model('CabBooking', cabBookingSchema);

export default CabBooking;
