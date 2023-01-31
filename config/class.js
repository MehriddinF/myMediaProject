const { v4: uuid } = require('uuid')
const fs = require('fs')
const path = require('path')
const bcrypt = require('bcryptjs');


module.exports = class MediaClass {
    constructor(Model, request, response, next) {
        this.Model = Model;
        this.res = response
        this.req = request
        this.next = next
    }
    // Fayl ishtirok etmagan holda malumot yaratish
    async CREATE_DATA() {
        const UUID = { uuid: uuid() }
        const body = { ...this.req.body }
        const files = this.req.files;
        if (files == "" || files == undefined || !files) {
            
            const result = await this.Model.create(Object.assign(body, UUID,))
            result.save()
                .then(() => {
                    this.res.json({ message: "Success", status: true, data: result })
                })
                .catch((error) => {
                    this.res.json({ message: "Failed", status: false, data: error.message })
                })
        }
        else {
            
            const arraysFiles = []
            for (const file of files) {
                const { filename } = file
                arraysFiles.push(filename)
            }
            const img = { image: arraysFiles }
            const result = await this.Model.create(Object.assign(body, img, UUID,))
            result.save()
                .then(() => {
                    this.res.json({ message: "Success", status: true, data: result })
                })
                .catch((error) => {
                    this.res.json({ message: "Failed", status: false, data: error.message })
                })
        }


    }
    // Alohida malumotni olish
    async GET_ONE(...populate) {
        try {
            const data = await this.Model
                .findById(this.req.params.id)
                .populate([...populate])

            this.res.json({ message: "Success", status: true, data: data })
        }
        catch (error) {
            this.res.json({ message: "Failed", status: false, data: error.message })
        }
    }
    // Hamma malumotni olish
    async GET_ALL(...populate) {
        try {
            const data = await this.Model
                .find()
                .populate([...populate])
                .sort({ date: -1 })
                .lean()

            this.res.json({ message: "Success", status: true, count: data.length, data: data })
        }
        catch (error) {
            this.res.json({ message: "Failed", status: false, data: error.message })
        }
    }
    // Alohida o'chirish
    async DELETE_without_file() {
        try {
            await this.Model
                .findByIdAndDelete(this.req.params.id)
            this.res.json({ message: "Success", status: true, data: [] })
        }
        catch (error) {
            this.res.json({ message: "Failed", status: false, data: error.message })
        }
    }
    // Alohida update qilish
    async UPDATE_without_file(folder) {
        const body = { ...this.req.body }
        const files = this.req.files;

        if (files == "" || files == undefined || !files) {
            const result = await this.Model.findByIdAndUpdate({ _id: this.req.params.id })
            Object.assign(result, body)
            result.save()
                .then(() => {
                    this.res.json({ message: "Success", status: true, data: result })
                })
                .catch((error) => {
                    this.res.json({ message: "Failed", status: false, data: error.message })
                })
        }
        else {
            // Esli faylni o'chirish
            const foundData = await this.Model.findById({ _id: this.req.params.id })
            const image = foundData.image // [ '1.jpg' ]
            image.forEach((img) => {
                fs.unlink(path.join(__dirname, `../public/${folder}/${img}`), () => { [] })
            });
            // Yangisiga almashtirish

            const arraysFiles = []
            for (const file of files) {
                const { filename } = file
                arraysFiles.push(filename)
            }
            const img = { image: arraysFiles }
            const result = await this.Model.findByIdAndUpdate({ _id: this.req.params.id })

            const defaults = Object.assign(body, img)
            Object.assign(result, defaults)
            result.save()
                .then(() => {
                    this.res.json({ message: "Success", status: true, data: result })
                })
                .catch((error) => {
                    this.res.json({ message: "Failed", status: false, data: error.message })
                })
        }




    }
    // Qaysidir key boyicha hamma malumotlarni olish
    async FILTER(...populate) {
        try {
            const { key, value } = this.req.query;
            const result = await this.Model
                .find({ [key]: value })
                .populate([...populate])
                .lean()
            this.res.json({ message: "Success", status: false, data: result })
        }
        catch (error) {
            this.res.json({ message: "Failed", status: false, data: error.message })
        }
    }
    // Faylli obyektlari o'chirish
    async DELETE_with_file(folder) {
        try {
            // Esli faylni o'chirish
            const foundData = await this.Model.findById({ _id: this.req.params.id })
            const image = foundData.image // [ '1.jpg' ]
            image.forEach((img) => {
                fs.unlink(path.join(__dirname, `../public/${folder}/${img}`), () => { [] })
            });
            await this.Model.findByIdAndDelete({ _id: this.req.params.id })
            this.res.json({ message: "Deleted", status: true, data: [] })
        }
        catch (error) {
            this.res.json({ message: "Failed", status: false, data: error.message })
        }
    }









}



