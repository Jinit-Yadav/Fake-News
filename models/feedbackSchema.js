import mongoose from 'mongoose';

const feedbackSchema = new mongoose.Schema({
  username: { type: String, required: true },
  feedbackText: { type: String, required: true },
  date: { type: Date, default: Date.now }
});

const Feedback = mongoose.model('Feedback', feedbackSchema);

export default Feedback;
