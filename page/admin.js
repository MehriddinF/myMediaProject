const express = require('express')
const router = express.Router()


router.get("/admin/dashboard", (req, res, next) => {
    res.render("./admin/dashboard.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/age", (req, res, next) => {
    res.render("./admin/age.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/category", (req, res, next) => {
    res.render("./admin/category.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/country", (req, res, next) => {
    res.render("./admin/country.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/genre", (req, res, next) => {
    res.render("./admin/genre.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/language", (req, res, next) => {
    res.render("./admin/language.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/quality", (req, res, next) => {
    res.render("./admin/quality.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/year", (req, res, next) => {
    res.render("./admin/year.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/advertisement", (req, res, next) => {
    res.render("./admin/advertisement.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/application", (req, res, next) => {
    res.render("./admin/application.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/buysubscription", (req, res, next) => {
    res.render("./admin/buysubscription.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/card", (req, res, next) => {
    res.render("./admin/card.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/cast", (req, res, next) => {
    res.render("./admin/cast.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/comment", (req, res, next) => {
    res.render("./admin/comment.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/mixed", (req, res, next) => {
    res.render("./admin/mixed.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/promocode", (req, res, next) => {
    res.render("./admin/promocode.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/rating", (req, res, next) => {
    res.render("./admin/rating.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/replycomment", (req, res, next) => {
    res.render("./admin/replycomment.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/seelater", (req, res, next) => {
    res.render("./admin/seelater.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/subscription", (req, res, next) => {
    res.render("./admin/subscription.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/trailer", (req, res, next) => {
    res.render("./admin/trailer.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/user", (req, res, next) => {
    res.render("./admin/user.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/vacancy", (req, res, next) => {
    res.render("./admin/vacancy.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})
router.get("/admin/video", (req, res, next) => {
    res.render("./admin/video.ejs", { layout: "./layout/admin.ejs", title: "Admin" })
})










module.exports = router