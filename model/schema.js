const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

// Faylsiz holati
const Quality = mongoose.model("quality", mongoose.Schema({
    name: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))
const Language = mongoose.model("language", mongoose.Schema({
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    date: { type: Date, default: Date.now() }
}))
const Category = mongoose.model("category", mongoose.Schema({
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    date: { type: Date, default: Date.now() }
}))
const Country = mongoose.model("country", mongoose.Schema({
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    date: { type: Date, default: Date.now() }
}))
const Genre = mongoose.model("genre", mongoose.Schema({
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    date: { type: Date, default: Date.now() }
}))
const Year = mongoose.model("year", mongoose.Schema({
    name: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))
const Age = mongoose.model("age", mongoose.Schema({
    name: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))


const Application = mongoose.model("application", mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    status: {
        type: String, required: true,
        enum: [
            "1", // tekshirilgan
            "0"  // tekshirilmagan
        ],
        default: "0"
    },
    date: { type: Date, default: Date.now() }

}))
const Vacancy = mongoose.model("vacancy", mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    status: {
        type: String, required: true,
        enum: [
            "1", // tekshirilgan
            "0"  // tekshirilmagan
        ],
        default: "0"
    },
    date: { type: Date, default: Date.now() }

}))
const Promocode = mongoose.model("promocode", mongoose.Schema({
    promocode: { type: String, required: true }, // maxfiy kod
    deadline: { type: String, required: true }, // chegirma muddati
    discount: { type: String, required: true }, // chegirma miqdori - foizda
    date: { type: Date, default: Date.now() }
}))
const SeeLater = mongoose.model("see_later", mongoose.Schema({
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    video: { type: mongoose.Schema.ObjectId, ref: "video", required: true },
    date: { type: Date, default: Date.now() }
}))
const Rating = mongoose.model("rating", mongoose.Schema({
    rating: { type: String, enum: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], required: true },
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    video: { type: mongoose.Schema.ObjectId, ref: "video", required: true },
    date: { type: Date, default: Date.now() }
}))
const Comment = mongoose.model("comment", mongoose.Schema({
    like: { type: Number, default: 0 },
    dislike: { type: Number, default: 0 },
    message: { type: String, required: true },
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    video: { type: mongoose.Schema.ObjectId, ref: "video", required: true },
    date: { type: Date, default: Date.now() }
}))
const ReplyComment = mongoose.model("reply", mongoose.Schema({
    like: { type: Number, default: 0 },
    dislike: { type: Number, default: 0 },
    message: { type: String, required: true },
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    comment: { type: mongoose.Schema.ObjectId, ref: "comment", required: true },
    date: { type: Date, default: Date.now() }
}))
const BuySubscription = mongoose.model("buy_subscription", mongoose.Schema({
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    subscription: { type: mongoose.Schema.ObjectId, ref: "subscription", required: true },
    deadline_date: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))
const Card = mongoose.model("card", mongoose.Schema({
    user: { type: mongoose.Schema.ObjectId, ref: "user", required: true },
    card_type: { type: String, enum: ["Visa", "Humo", "Uzcard", "WebMoney", "Master Card"], required: true },
    card_number: { type: String, required: true },
    card_cvc: { type: String, required: true },
    validation_date: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))





// Fayl ishtirok etgan holati
const Cast = mongoose.model("cast", mongoose.Schema({
    name: { type: String, required: true },
    image: [{ type: String, required: true }],
    role: { type: String, required: true, enum: ["actor", "actress", "director"] },
    date: { type: Date, default: Date.now() }
}))
const Advertisement = mongoose.model("advertisement", mongoose.Schema({
    image: [{ type: String, required: true }],
    date: { type: Date, default: Date.now() }
}))
const User = mongoose.model("user", mongoose.Schema({
    name: { type: String, required: true },
    uuid: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    birth_month: { type: String, required: true },
    birth_day: { type: String, required: true },
    deadline: { type: String, default: "0" }, // tarifni tugash muddati
    status: { type: String, enum: ["vip", "none"], default: "none" }, // tarif olsa vip, tugasa none
    role: { type: String, required: true, enum: ["admin", "user", "moderator"] },
    image: [{ type: String, required: true }],
    balance: { type: Number, default: 0 },
    promocode: { type: mongoose.Schema.ObjectId, ref: "promocode" },
    setting: { type: String, enum: ["gift", "premier", "new video"] },
    date: { type: Date, default: Date.now() }
}))
const Subscription = mongoose.model("subscription", mongoose.Schema({
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    description: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    image: [{ type: String, required: true }],
    deadline: { type: String, required: true, enum: ["3 days", "1 week", "1 month", "3 month", "forever"] },
    price: { type: String, required: true },
    date: { type: Date, default: Date.now() }
}))
const Mixed = mongoose.model("mixed", mongoose.Schema({
    year: { type: mongoose.Schema.ObjectId, ref: "year", required: true },
    genre: { type: mongoose.Schema.ObjectId, ref: "genre", required: true },
    country: { type: mongoose.Schema.ObjectId, ref: "country", required: true },
    category: { type: mongoose.Schema.ObjectId, ref: "category", required: true },
    cast: { type: mongoose.Schema.ObjectId, ref: "cast", required: true },
    quality: { type: mongoose.Schema.ObjectId, ref: "quality", required: true },
    age: { type: mongoose.Schema.ObjectId, ref: "age", required: true },
    trailer: [{ type: String, required: true }],
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    description: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    block: {
        type: { type: String, enum: ["none", "forever", "short_time"], required: true },
        startDate: { type: String, default: "0" },
        endDate: { type: String, default: "0" },
    },
    payment: { type: String, enum: ["free", "pay"], required: true },
    status: { type: String, enum: ["move", "cartoon", "series"], required: true },
    price: { type: String, required: true }, // agar payment qism frr bolsa 0 yoziladi, aks holda summa yozilad
    date: { type: Date, default: Date.now() }
}))
const Video = mongoose.model("video", mongoose.Schema({
    mixed: { type: mongoose.Schema.ObjectId, ref: "mixed", required: true },
    name: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    description: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    plot: {
        uz: { type: String, required: true },
        ru: { type: String, required: true },
        en: { type: String, required: true },
    },
    video: [{ type: String, required: true }], // koriladigan video yoziladi
    image: [{ type: String, required: true }], // kinodan lavlalr beriladi
    trailer: [{ type: String, required: true }],
    imbd: { type: String, required: true },
    duration: { type: String, required: true },
    link: { type: String, required: true }, // videoni korish uchun link manzili beriladi
    rating: { type: String, default: 0 },
    date: { type: Date, default: Date.now() }
}))
const Trailer = mongoose.model("trailer", mongoose.Schema({
    trailer_video: [{ type: String, required: true }],
    video: { type: mongoose.Schema.ObjectId, ref: "video", required: true },
    date: { type: Date, default: Date.now() }
}))







module.exports = {
    Quality,
    Language,
    Category,
    Country,
    Genre,
    Year,
    Cast,
    Age,
    Advertisement,
    Application,
    Vacancy,
    Promocode,
    User,
    Subscription,
    BuySubscription,
    Card,
    Video,
    Mixed,
    SeeLater,
    Trailer,
    Rating,
    ReplyComment,
    Comment
}

// Payed list qismini qilish kerak