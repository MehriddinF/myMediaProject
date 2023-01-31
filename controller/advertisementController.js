const { Advertisement } = require('../model/schema')
const MediaClass = require('../config/class')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(Advertisement, req, res, next)
    my_class.CREATE_DATA()
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(Advertisement, req, res, next)
    my_class.GET_ONE()
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(Advertisement, req, res, next)
    my_class.GET_ALL()
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(Advertisement, req, res, next)
    my_class.UPDATE_without_file("advertisement")
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(Advertisement, req, res, next)
    my_class.DELETE_with_file("advertisement");
}