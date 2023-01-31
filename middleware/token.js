const { User } = require('../model/schema');
const { key } = require('../config/index')
const JWT = require('jsonwebtoken')

// @description: Token mavjud yoki mavjud emasligini tekshirish
exports.check_token = async (req, res, next) => {
    let token;
    const { authorization } = req.headers

    if (!authorization || authorization == "") {
        res.json({
            success: false,
            message: {
                uz: "Token mavjud emas",
                en: "Token is not defined"
            }
        })
    }
    else {
        if (authorization.startWith("Bearer")) {
            token = authorization.split(" ")[1];
        }
        else {
            res.json({
                success: false,
                message: {
                    uz: "Token mavjud emas -2 ",
                    en: "Token is not defined - 2"
                }
            })
        }
    }
    if (!token) {
        res.json({
            success: false,
            message: {
                uz: "Ushbu API bo'yicha malumot olish mumkin emas - 1",
                en: "No authorize to access this route - 1"
            }
        })
    }
    else {
        try {
            const decoded = JWT.verify(token, key);
            req.user = await User.findById(decoded.id);
            next();
        }
        catch (error) {
            res.json({
                success: false,
                message: error.message
            })
        }
    }
}
// @description: Foydalanuvchini role boyicha tekshirish
exports.check_role = async (...ROLES) => {
    return (req, res, next) => {
        if (!ROLES.includes(req.user.role)) {
            return next({
                success: false,
                message: {
                    uz: `Ushbu role egasi uchun malumot olish huququi mavjud emas`,
                    en: `User role ${req.user.role} is not authorized to access this route`
                }
            })
        }
        next()
    }

}

// @description: Foydalanuvchini bloklangan yoki bloklanmaganligini tekshirish
exports.check_block_system = async (...BLOCK) => {
    return (req, res, next) => {
        if (!BLOCK.includes(req.user.block_system)) {
            return next({
                success: false,
                message: {
                    uz: `Foydalanuvchi bloklangan`,
                    en: `User is blocked`
                }
            })
        }
        next()
    }
}

// @description: Foydalanuvchini tarif sotib olgan yoki yo'qligini tekshirish
exports.check_status = async (...STATUS) => {
    return (req, res, next) => {
        if (!STATUS.includes(req.user.status)) {
            return next({
                success: false,
                message: {
                    uz: `Tarif yoqilmagan `,
                    en: `Tariff is off`
                }
            })
        }
        next()
    }
}
