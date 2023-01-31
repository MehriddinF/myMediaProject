const { Video } = require('../model/schema')
const MediaClass = require('../config/class')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.CREATE_DATA()
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.GET_ONE("mixed")
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.GET_ALL("mixed")
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.UPDATE_without_file("video");
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.DELETE_with_file("video");
}
exports.filterData = async (req, res, next) => {
    const my_class = new MediaClass(Video, req, res, next)
    my_class.FILTER("mixed")
}
