const { User } = require('../model/schema')
const MediaClass = require('../config/class')
const bcrypt = require('bcryptjs')
const JWT = require('jsonwebtoken')
const { key, time } = require('../config/index')

exports.createData = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.CREATE_DATA()
}
exports.login = async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) res.json({ success: false, data: "Email or password are not defined " })
    else {
        const user = await User.find({ email: email }).select({ password })
        // Emailni tekshirish
        if (!user) { res.json({ success: false, data: "Email is not defined " }) }
        else {
            // Parolni  tekshirish
            const compare_password = await bcrypt.compare(password, user.password)
            if (!compare_password || compare_password == false) {
                res.json({ success: false, data: "Email is not defined " })
            }
            else {

                const token = JWT.sign(
                    {
                        id: user._id,
                    },
                    key,
                    { expiresIn: time }
                )
                res.json({ success: true, token: token })
            }
        }
    }
}
exports.getOne = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.GET_ONE()
}
exports.getAll = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.GET_ALL()
}
exports.updateOne = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.UPDATE_without_file("user")
}
exports.deleteOne = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.DELETE_with_file("user")
}
exports.filterData = async (req, res, next) => {
    const my_class = new MediaClass(User, req, res, next)
    my_class.FILTER("promocode")
}

