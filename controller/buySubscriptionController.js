const { BuySubscription } = require('../model/schema')
const MediaClass = require('../config/class')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.CREATE_DATA()
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.GET_ONE("user", "subscription")
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.GET_ALL("user", "subscription")
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.UPDATE_without_file()
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.DELETE_without_file()
}
exports.filterData= async (req, res, next) => {
    const my_class = new MediaClass(BuySubscription, req, res, next)
    my_class.FILTER("user", "subscription")
}