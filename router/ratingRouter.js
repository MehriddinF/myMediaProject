const router = require('express').Router()
const Controller = require("../controller/ratingController")


router.post("/create", Controller.createData)
router.get("/all", Controller.getAll)
router.get("/filter/:id", Controller.filterData)
router.get("/:id", Controller.getOne)
router.put("/:id", Controller.updateOne)
router.delete("/:id", Controller.deleteOne)

module.exports = router