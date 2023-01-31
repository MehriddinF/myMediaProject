const express = require('express')
const router = express.Router()


// www.mediahouse.uz
router.get("/", (req, res, next) => {
    res.render("./client/index.ejs", { layout: "./layout/client.ejs", title: "Hot Flix" })
})


module.exports = router