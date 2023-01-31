// Requirement
const express = require('express')
const app = express()
const path = require('path')
const bodyParser = require('body-parser')
const cors = require("cors")
const expressEjsLayouts = require("express-ejs-layouts")
const i18n = require("i18n-express");
const fs = require('fs')
const cookieParser = require("cookie-parser");
const expressSession = require("express-session")
const connectMongodbSession = require("connect-mongodb-session")(expressSession)
const { port, key, time, session, database } = require('./config/index')
const databaseConnection = require('./database/db')
const AdminPageRouter = require("./page/admin")
const ClientPageRouter = require("./page/client")
const AuthPageRouter = require("./page/auth")
const FOLDER = require("./config/folder")

const SessionDatabase = new connectMongodbSession({
    uri: database,
    collection: session,
})
// Set up
FOLDER()
app.use(express.static(path.join(__dirname, "public")))
app.set("views", path.join(__dirname, "views"))
app.set("view engine", "ejs")
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cors({ origin: "*" }))
app.use(expressEjsLayouts)
app.use(cookieParser())
app.use(i18n({
    translationsPath: path.join(__dirname, 'i18n'), // <--- use here. Specify translations files path.
    siteLangs: ["uz", "ru", "en"],
    textsVarName: 'translation'
}))
app.use(expressSession({
    secret: key,
    resave: false,
    saveUninitialized: false,
    store: SessionDatabase,
    cookie: {
        httpOnly: true,
        maxAge: time,
        sameSite: "strict",
    }
}))


// Frontend page Router
app.use(ClientPageRouter)
app.use(AuthPageRouter)
app.use(AdminPageRouter)



// Backend page Router
app.use("/api/quality", require('./router/qualityRouter'))
app.use("/api/language", require('./router/languageRouter'))
app.use("/api/category", require('./router/categoryRouter'))
app.use("/api/country", require('./router/countryRouter'))
app.use("/api/genre", require('./router/genreRouter'))
app.use("/api/year", require('./router/yearRouter'))
app.use("/api/age", require('./router/ageRouter'))
app.use("/api/application", require('./router/applicationRouter'))
app.use("/api/vacancy", require('./router/vacancyRouter'))
app.use("/api/promocode", require('./router/promocodeRouter'))
app.use("/api/seeLater", require('./router/seeLaterRouter'))
app.use("/api/comment", require('./router/commentRouter'))
app.use("/api/reply", require('./router/replyCommentRouter'))
app.use("/api/buy_subscription", require('./router/buySubscriptionRouter'))
app.use("/api/card", require('./router/cardRouter'))
app.use("/api/rating", require('./router/ratingRouter'))

app.use("/api/cast", require('./router/castRouter'))
app.use("/api/advertisement", require('./router/advertisementRouter'))
app.use("/api/subscription", require('./router/subscriptionRouter'))
app.use("/api/user", require('./router/userRouter'))
app.use("/api/mixed", require('./router/mixedRouter'))
app.use("/api/video", require('./router/videoRouter'))
app.use("/api/trailer", require('./router/trailerRouter'))









// Databazani ulash
databaseConnection()
// Serverni ishga tushirish
const server = app.listen(port, () => console.log("Server is running", server.address().port))