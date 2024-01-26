const express = require('express');
const app = express();
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

//Set routes
const  users = require('./routes/UserRoutes');
app.use('/users', users);

//Setup static files
app.use(express.static('public'));

//Setup database
mongoose.connect('mongodb://localhost:27017/login',{ useNewUrlParser: true,
useUnifiedTopology: true })
    .then(() => console.log('Database connected'))
    .catch(err => console.log(err));

//Setup user authention
const User = require('./models/User');
// new LocalStrategy ใช้เพื่อตรวจสอบผู้ใช้ในฐานข้อมูล => User.findOne
passport.use(new LocalStrategy((username, password, done) => {
    User.findOne({ username: username, password: password}, (err, user) => {
        if(err) { return done(err); }
        if(!user) { return done(null, false, { msg: 'Incorrect username or password'}); }
        //bcrypt.compare 
        // เพื่อเปรียบเทียบรหัสผ่านที่ผู้ใช้ป้อนเข้ามากับรหัสผ่านที่ถูกเข้ารหัสไว้ในฐานข้อมูลโดยใช้ bcrypt. 
        // ถ้ารหัสผ่านตรงกัน
        bcrypt.compare(password, user.password, (err, res) => {
            if(err) { return done(err); }
            if(!res) { return done(null, false, { msg: 'Incorrect username or password'}); }
        
            // ถ้ารหัสผ่านตรงกัน
            return done(null, user);
        });
    });
}));
//Passport middleware สำหรับตรวจสอบการรับรองตัวตนใน Node.js => Express.js
//passport.serializeUser() 
// - ฟังก์ชันนี้ใช้เพื่อกำหนดวิธีการแปลงข้อมูลผู้ใช้ให้เป็นรหัส (user.id) ซึ่งจะถูกเก็บไว้ใน session.
// - done คือฟังก์ชันที่คุณเรียกเมื่อเสร็จสิ้นการ serialize และจะมีการเรียกต่อไปในขั้นตอนที่เกี่ยวข้อง.
passport.serializeUser((user, done) => {
    done(null, user.id);
});
//passport.deserializeUser() 
// - ฟังก์ชันนี้ใช้เพื่อดึงข้อมูลผู้ใช้จากรหัสที่ถูกเก็บไว้ใน session (id).
// - User.findById คือฟังก์ชันที่ใช้ในการค้นหาผู้ใช้จากฐานข้อมูลโดยใช้รหัส id.
// - เมื่อค้นพบข้อมูลผู้ใช้, done จะถูกเรียกโดย Passport และจะนำข้อมูลผู้ใช้ไปใช้งานต่อ.
passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port localhost:${PORT}`));