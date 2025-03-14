import mongoose from "mongoose";

const oliveSchema = mongoose.Schema({
    location: {
        type: {
            type: String,
            enum: ['Point'],
            required: true,
        },
        coordinates: {
            type: [Number],
            required: true,
        }
    },
    createdAt: {
        type: Date,
        required: true,
        default: Date.now,
        // expires: 10,
    }
});

oliveSchema.index({ location: '2dsphere' });

const Olive = mongoose.model('Olive', oliveSchema);

export default Olive;