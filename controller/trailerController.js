const { Trailer } = require('../model/schema')
const MediaClass = require('../config/class')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.CREATE_DATA()
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.GET_ONE("video")
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.GET_ALL("video")
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.UPDATE_without_file("trailer");
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.DELETE_with_file("trailer");
}
exports.filterData = async (req, res, next) => {
    const my_class = new MediaClass(Trailer, req, res, next)
    my_class.FILTER("video")
}