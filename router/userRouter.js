const router = require('express').Router()
const Controller = require("../controller/userController")
const path = require('path')
const fs = require('fs')
const md5 = require('md5')
const multer = require('multer')

const folder = "./public/user"
const limitFile = 5

// Faylni yuklash uchun
const uploading = multer({
    storage: multer.diskStorage({
        destination: function (req, file, callback) {
            callback(null, folder)
        },
        filename: function (req, file, callback) {
            callback(null, `${md5(Date.now())}${path.extname(file.originalname)}`)
        }
    })
})

router.post("/create", uploading.array("image", limitFile), Controller.createData)
router.post("/login", Controller.login)
router.get("/filter", Controller.filterData)
router.get("/all", Controller.getAll)
router.get("/:id", Controller.getOne)
router.put("/:id", uploading.array("image", limitFile), Controller.updateOne)
router.delete("/:id", Controller.deleteOne)

module.exports = router