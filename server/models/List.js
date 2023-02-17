import mongoose from "mongoose";
const { Schema } = mongoose;

const listSchema = new Schema ({
    text: {type: String,
        required: true,
    },
    author: {
        type: String,
        default: "demian",
    },
    isCompleted: {
        type: Boolean,
        default: false
    } ,
    createdAt: {
        type: Date,
        default: new Date(),
    },
})
const List = mongoose.model('List', listSchema);
export default List;