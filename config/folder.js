const fs = require('fs')
const path = require('path')

const createFolder = () => {
    // Papkalarni yaratish
    fs.mkdir(path.join(__dirname, "./public/cast"), (error, callback) => {
        if (error) console.log("CAST papka allaqachon mavjud")
        else console.log("CAST papka  yaratildi")
    })
    fs.mkdir(path.join(__dirname, "./public/advertisement"), (error, callback) => {
        if (error) console.log("ADVERTISEMENT papka allaqachon mavjud")
        else console.log("ADVERTISEMENT papka  yaratildi")
    })
    fs.mkdir(path.join(__dirname, "./public/user"), (error, callback) => {
        if (error) console.log("USER papka allaqachon mavjud")
        else console.log("USER papka  yaratildi")
    })
    fs.mkdir(path.join(__dirname, "./public/subscription"), (error, callback) => {
        if (error) console.log("SUBSCRIPTION papka allaqachon mavjud")
        else console.log("SUBSCRIPTION papka  yaratildi")
    })
    fs.mkdir(path.join(__dirname, "./public/mixed"), (error, callback) => {
        if (error) console.log("MIXED papka allaqachon mavjud")
        else console.log("MIXED papka  yaratildi")
    })
    fs.mkdir(path.join(__dirname, "./public/video"), (error, callback) => {
        if (error) console.log("VIDEO papka allaqachon mavjud")
        else console.log("VIDEO papka  yaratildi")
    })
}

module.exports = createFolder