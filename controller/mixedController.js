const { Mixed } = require('../model/schema')
const MediaClass = require('../config/class')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.CREATE_DATA()
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.GET_ONE("year", "genre", "country", "category", "cast", "quality", "age",)
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.GET_ALL("year", "genre", "country", "category", "cast", "quality", "age",)
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.UPDATE_without_file("mixed");
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.DELETE_with_file("mixed");
}
exports.filterData = async (req, res, next) => {
    const my_class = new MediaClass(Mixed, req, res, next)
    my_class.FILTER("year", "genre", "country", "category", "cast", "quality", "age",)
}
