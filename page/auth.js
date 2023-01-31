const express = require('express')
const router = express.Router()

router.get("/sign-in", (req, res, next) => {
    res.render("./auth/login.ejs", { layout: "./layout/auth.ejs", title: "Sign-in" })
})
router.get("/sign-up", (req, res, next) => {
    res.render("./auth/register.ejs", { layout: "./layout/auth.ejs", title: "Sign-up" })
})
router.get("/forget-password", (req, res, next) => {
    res.render("./auth/forgotpassword.ejs", { layout: "./layout/auth.ejs", title: "Forget password" })
})


module.exports = router